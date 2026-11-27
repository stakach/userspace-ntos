//! Compile both native contended-wait tails with an exact Signal lease still in flight.
//!
//! A broker wake may resume a waiter before `KeSetEvent` returns. The waiter must transfer its
//! allocation-backed Event to a deferred owner, then return without freeing the signaler's body.

use std::process::Command;

#[test]
fn successful_contended_waits_transfer_event_until_signaler_releases_its_lease() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let resource = extract(
        source,
        "fn acquire_resource_lite(",
        "\n/// `BOOLEAN ExAcquireResourceExclusiveLite",
    );
    let mutex_native = extract(
        source,
        "extern \"win64\" fn s_ex_acquire_fast_mutex_unsafe(",
        "\n/// `VOID ExReleaseFastMutexUnsafe",
    );
    syn::parse_str::<syn::ItemFn>(resource).expect("production ERESOURCE acquisition parses");
    syn::parse_str::<syn::ItemFn>(mutex_native).expect("production FastMutex acquisition parses");
    // The host Rust compiler on macOS does not provide the Windows x64 calling convention.
    let mutex = mutex_native.replacen("extern \"win64\"", "extern \"C\"", 1);
    let fixture = format!("{MOCKS}\n{resource}\n{mutex}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-win32k-resource-retire-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native wait fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        result.status.success(),
        "native deferred Event interleaving:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn production_finalizer_retires_before_free_and_retains_uncertain_ownership() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let finalizer = extract(
        source,
        "unsafe fn finish_temporary_wait_event_retirement(",
        "\nunsafe fn retire_existing_provider_local_timer",
    );
    syn::parse_str::<syn::ItemFn>(finalizer).expect("production Event finalizer parses");
    let fixture = format!("{FINALIZER_MOCKS}\n{finalizer}\n{FINALIZER_CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-win32k-event-finalizer-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native Event finalizer fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        result.status.success(),
        "native Event finalizer ownership:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn extract<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).expect("native method");
    let finish = source[begin..]
        .find(end)
        .map(|offset| begin + offset)
        .expect("end of native method");
    &source[begin..finish]
}

const MOCKS: &str = r#"
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}};
const EVENT_CANARY: u64 = 0xe117_e117_e117_e117;
static EVENT_BODY: AtomicU64 = AtomicU64::new(0);
static SIGNAL_LEASE: AtomicBool = AtomicBool::new(false);
static DELETE_PENDING: AtomicBool = AtomicBool::new(false);
static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
static PARKED: AtomicBool = AtomicBool::new(false);
static DEFERRED_STORAGE: Mutex<Option<Box<[u64; 3]>>> = Mutex::new(None);

mod nt_kernel_exec {
    pub mod executive_sync {
        #[derive(Clone, Copy)]
        pub enum ResourceMode { Exclusive }
        pub enum AcquireResult { Acquired, WouldBlock }
        pub enum ResourceWaitAdmission { Acquired, Queued(u64) }
        pub enum FastMutexWaitAdmission { Acquired, Queued(u64) }
        #[derive(Clone, Copy, Debug)]
        pub enum ExecutiveSyncError { BlockingWaitRequired }
        pub fn acquire_fast_mutex_unsafe(_: *mut u8, _: u64)
            -> Result<AcquireResult, ExecutiveSyncError> { Ok(AcquireResult::WouldBlock) }
    }
}
mod nt_provider_wait {
    pub enum ProviderWaitPrimitive { AcquireResource, AcquireFastMutex }
    pub enum ProviderWaitType { Any }
}
struct MockResources;
impl MockResources {
    fn acquire(&mut self, _: *mut u8, _: u64,
        _: nt_kernel_exec::executive_sync::ResourceMode)
        -> Result<nt_kernel_exec::executive_sync::AcquireResult,
            nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        Ok(nt_kernel_exec::executive_sync::AcquireResult::WouldBlock)
    }
    fn begin_wait(&mut self, _: *mut u8, _: u64,
        _: nt_kernel_exec::executive_sync::ResourceMode, body: u64)
        -> Result<nt_kernel_exec::executive_sync::ResourceWaitAdmission,
            nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        assert_eq!(body, EVENT_BODY.load(Ordering::SeqCst));
        Ok(nt_kernel_exec::executive_sync::ResourceWaitAdmission::Queued(73))
    }
    fn complete_wait(&mut self, _: *mut u8, _: u64, ticket: u64)
        -> Result<(), nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        assert_eq!(ticket, 73);
        Ok(())
    }
    fn cancel_wait(&mut self, _: *mut u8, _: u64, _: u64)
        -> Result<Option<u64>, nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        panic!("a successful wait must not cancel its ticket")
    }
}
struct MockFastMutexWaits;
impl MockFastMutexWaits {
    fn begin_wait(&mut self, _: *mut u8, _: u64, body: u64)
        -> Result<nt_kernel_exec::executive_sync::FastMutexWaitAdmission,
            nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        assert_eq!(body, EVENT_BODY.load(Ordering::SeqCst));
        Ok(nt_kernel_exec::executive_sync::FastMutexWaitAdmission::Queued(91))
    }
    fn complete_wait(&mut self, _: *mut u8, _: u64, ticket: u64)
        -> Result<(), nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        assert_eq!(ticket, 91);
        Ok(())
    }
    fn cancel_wait(&mut self, _: *mut u8, _: u64, _: u64)
        -> Result<Option<u64>, nt_kernel_exec::executive_sync::ExecutiveSyncError> {
        panic!("a successful wait must not cancel its ticket")
    }
}
static mut RESOURCES: MockResources = MockResources;
static mut FAST_MUTEX_WAITS: MockFastMutexWaits = MockFastMutexWaits;
fn executive_resources_mut() -> &'static mut MockResources { unsafe { &mut RESOURCES } }
fn fast_mutex_waits_mut() -> &'static mut MockFastMutexWaits { unsafe { &mut FAST_MUTEX_WAITS } }
unsafe fn current_ethread() -> u64 { 0x4080_000a_2000 }

// The compiled production wait methods use this mock lifetime API. Catalog receipt and exact
// backing checks are exercised separately by the host catalog tests and native build.
struct TemporaryWaitEvent { body: u64, storage: Option<Box<[u64; 3]>> }
impl TemporaryWaitEvent {
    unsafe fn publish() -> Self {
        let mut storage = Box::new([0u64; 3]);
        storage[0] = EVENT_CANARY;
        let body = storage.as_mut_ptr() as u64;
        EVENT_BODY.store(body, Ordering::SeqCst);
        Self { body, storage: Some(storage) }
    }
    unsafe fn retire(mut self) -> bool {
        assert_eq!(self.body, EVENT_BODY.load(Ordering::SeqCst));
        assert_eq!((self.body as *const u64).read(), EVENT_CANARY);
        let storage = self.storage.take().unwrap();
        if SIGNAL_LEASE.load(Ordering::SeqCst) {
            DELETE_PENDING.store(true, Ordering::SeqCst);
            assert!(DEFERRED_STORAGE.lock().unwrap().replace(storage).is_none());
        } else {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            drop(storage);
            FREES.fetch_add(1, Ordering::SeqCst);
        }
        true
    }
}
unsafe fn provider_wait_rendezvous(_: nt_provider_wait::ProviderWaitPrimitive,
    bodies: &[u64], _: nt_provider_wait::ProviderWaitType,
    _: u8, _: u8, _: u64) -> i32 {
    assert_eq!(bodies, &[EVENT_BODY.load(Ordering::SeqCst)]);
    // The Wait lease has settled but the signaler still owns exact access to this Event body.
    SIGNAL_LEASE.store(true, Ordering::SeqCst);
    0
}
fn finish_signal() -> bool {
    let storage = DEFERRED_STORAGE.lock().unwrap().take();
    let Some(storage) = storage else { return false; };
    assert_eq!(storage[0], EVENT_CANARY);
    SIGNAL_LEASE.store(false, Ordering::SeqCst);
    RETIREMENTS.fetch_add(1, Ordering::SeqCst);
    drop(storage);
    FREES.fetch_add(1, Ordering::SeqCst);
    DELETE_PENDING.store(false, Ordering::SeqCst);
    true
}
fn reset() {
    assert!(DEFERRED_STORAGE.lock().unwrap().is_none());
    EVENT_BODY.store(0, Ordering::SeqCst);
    SIGNAL_LEASE.store(false, Ordering::SeqCst);
    DELETE_PENDING.store(false, Ordering::SeqCst);
    RETIREMENTS.store(0, Ordering::SeqCst);
    FREES.store(0, Ordering::SeqCst);
    PARKED.store(false, Ordering::SeqCst);
}
fn s_ke_set_event(_: u64, _: u64, _: u64) -> i32 {
    panic!("successful wait must not signal cancellation")
}
fn trace_resource_queue(_: u64, _: u64,
    _: nt_kernel_exec::executive_sync::ResourceMode) {}
fn print_str(_: &[u8]) {}
fn print_win32k_hex64(_: u64) {}
fn print_hex(_: u32) {}
fn park() -> ! {
    PARKED.store(true, Ordering::SeqCst);
    panic!("provider parked while an exact Signal lease was draining")
}
fn reject_resource_sync(_: &'static [u8],
    _: nt_kernel_exec::executive_sync::ExecutiveSyncError,
    _: u64, _: u64) -> ! {
    panic!("successful resource wait must not reject acquisition")
}
fn reject_fast_mutex_sync(_: &'static [u8],
    _: nt_kernel_exec::executive_sync::ExecutiveSyncError,
    _: u64, _: u64) -> ! {
    panic!("successful FastMutex wait must not reject acquisition")
}
"#;

const CASES: &str = r#"
fn check_deferred_signal() {
    assert!(SIGNAL_LEASE.load(Ordering::SeqCst));
    assert!(DELETE_PENDING.load(Ordering::SeqCst));
    assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 0);
    assert_eq!(FREES.load(Ordering::SeqCst), 0);
    assert!(!PARKED.load(Ordering::SeqCst));
    assert!(finish_signal());
    assert!(!finish_signal(), "a second finalization cannot free or ACK again");
    assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 1);
    assert_eq!(FREES.load(Ordering::SeqCst), 1);
    assert!(!DELETE_PENDING.load(Ordering::SeqCst));
}
#[test]
fn resumed_resource_waiter_transfers_owned_event() {
    reset();
    let result = acquire_resource_lite(
        0x1000, true,
        nt_kernel_exec::executive_sync::ResourceMode::Exclusive,
        b"ExAcquireResourceExclusiveLite",
    );
    assert_eq!(result, 1);
    check_deferred_signal();
}
#[test]
fn resumed_fast_mutex_waiter_transfers_owned_event() {
    reset();
    s_ex_acquire_fast_mutex_unsafe(0x2000);
    check_deferred_signal();
}
"#;

const FINALIZER_MOCKS: &str = r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod nt_provider_wait {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ProviderEventBacking { Allocation { allocation_id: u64 }, Stack { lane_id: u64 } }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ProviderEventStorage { pub backing: ProviderEventBacking, pub offset: u64 }
    pub struct ProviderLocalEventRetirement {
        body: u64,
        storage: ProviderEventStorage,
    }
    impl ProviderLocalEventRetirement {
        pub fn new(body: u64, storage: ProviderEventStorage) -> Self { Self { body, storage } }
        pub fn body(&self) -> u64 { self.body }
        pub fn storage(&self) -> ProviderEventStorage { self.storage }
    }
}
mod nt_kernel_exec {
    pub mod kevent {
        pub mod kevent_layout { pub const SIZE_OF: usize = 24; }
    }
}
use nt_provider_wait::{ProviderEventBacking, ProviderEventStorage, ProviderLocalEventRetirement};

static RETIRE_SUCCEEDS: AtomicBool = AtomicBool::new(true);
static RETIRE_CALLS: AtomicUsize = AtomicUsize::new(0);
static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);

unsafe fn retire_provider_local_event(retirement: ProviderLocalEventRetirement) -> bool {
    assert_eq!(retirement.body(), 0x8100);
    assert_eq!(retirement.storage().backing,
        ProviderEventBacking::Allocation { allocation_id: 81 });
    assert_eq!(PHASE.swap(1, Ordering::SeqCst), 0,
        "canonical RETIRE/ACK must precede pool release");
    RETIRE_CALLS.fetch_add(1, Ordering::SeqCst);
    RETIRE_SUCCEEDS.load(Ordering::SeqCst)
}

unsafe fn provider_pool_release_owned_exact(
    pointer: u64, required: u64, backing: ProviderEventBacking,
) -> bool {
    assert_eq!(PHASE.swap(2, Ordering::SeqCst), 1,
        "pool release must follow canonical RETIRE/ACK");
    assert_eq!(pointer, 0x8100);
    assert_eq!(required, 24);
    assert_eq!(backing, ProviderEventBacking::Allocation { allocation_id: 81 });
    FREE_CALLS.fetch_add(1, Ordering::SeqCst);
    true
}
"#;

const FINALIZER_CASES: &str = r#"
fn receipt(storage: ProviderEventStorage) -> ProviderLocalEventRetirement {
    ProviderLocalEventRetirement::new(0x8100, storage)
}
fn allocation(offset: u64) -> ProviderEventStorage {
    ProviderEventStorage {
        backing: ProviderEventBacking::Allocation { allocation_id: 81 }, offset,
    }
}
fn reset() {
    RETIRE_SUCCEEDS.store(true, Ordering::SeqCst);
    RETIRE_CALLS.store(0, Ordering::SeqCst);
    FREE_CALLS.store(0, Ordering::SeqCst);
    PHASE.store(0, Ordering::SeqCst);
}
#[test]
fn exact_allocation_retires_before_free() {
    reset();
    assert!(unsafe { finish_temporary_wait_event_retirement(receipt(allocation(0))) });
    assert_eq!((RETIRE_CALLS.load(Ordering::SeqCst), FREE_CALLS.load(Ordering::SeqCst)), (1, 1));
    assert_eq!(PHASE.load(Ordering::SeqCst), 2);
}
#[test]
fn uncertain_canonical_retirement_keeps_allocation_owned() {
    reset();
    RETIRE_SUCCEEDS.store(false, Ordering::SeqCst);
    assert!(!unsafe { finish_temporary_wait_event_retirement(receipt(allocation(0))) });
    assert_eq!((RETIRE_CALLS.load(Ordering::SeqCst), FREE_CALLS.load(Ordering::SeqCst)), (1, 0));
    assert_eq!(PHASE.load(Ordering::SeqCst), 1);
}
#[test]
fn crossed_storage_is_refused_before_canonical_retirement() {
    reset();
    assert!(!unsafe { finish_temporary_wait_event_retirement(receipt(allocation(8))) });
    assert!(!unsafe { finish_temporary_wait_event_retirement(receipt(ProviderEventStorage {
        backing: ProviderEventBacking::Stack { lane_id: 9 }, offset: 0,
    })) });
    assert_eq!((RETIRE_CALLS.load(Ordering::SeqCst), FREE_CALLS.load(Ordering::SeqCst)), (0, 0));
    assert_eq!(PHASE.load(Ordering::SeqCst), 0);
}
"#;
