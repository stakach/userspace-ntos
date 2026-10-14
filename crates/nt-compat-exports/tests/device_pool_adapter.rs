//! Executes the native adapter unchanged with host pool-memory/locking effects.
//! This is not native execution or a replacement implementation of pool retirement.
use core::ptr::{read_unaligned, read_volatile, write_volatile, write_unaligned};
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, HostedDomainIdentity, IoManager,
    MockDriverBackend, MockObjectPort, WDM_X64_DEVICE_OBJECT_SIZE, WDM_X64_DRIVER_OBJECT_SIZE,
    WDM_X64_FILE_OBJECT_SIZE,
    WDM_X64_IO_TYPE_DEVICE, WDM_X64_IO_TYPE_DRIVER,
};
use nt_types::NtPath;

const FSD_POOL_VADDR: u64 = 0x400000;
const FSD_POOL_FRAMES: u64 = 2;
const POOL_DATA_OFF: u64 = 0x1000;
const PAYLOAD: u64 = POOL_DATA_OFF + 16;
const ADDRESS: u64 = FSD_POOL_VADDR + PAYLOAD;
const CAPACITY: u64 = 0x200;
const POOL_FREE_LIST_MAX: u64 = FSD_POOL_FRAMES * 0x1000 / 16;
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct DriverInstance {
    used: bool,
    exec_pool_va: u64,
    pool_frame_base: u64,
    pml4: u64,
    domain: HostedDomainIdentity,
}

fn instance_domain_identity(inst: DriverInstance) -> Option<HostedDomainIdentity> {
    Some(inst.domain)
}

mod allocator {
    pub struct Durable;
    pub fn enter_durable() -> Durable { Durable }
}

thread_local! {
    static POOL_LOCK: Cell<Option<u64>> = const { Cell::new(None) };
    static EVENTS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    static MANAGER: Cell<*mut IoManager<MockObjectPort>> = const { Cell::new(core::ptr::null_mut()) };
    static REFUSE_PUBLICATION: Cell<bool> = const { Cell::new(false) };
    static ACCEPTED: Cell<Option<nt_io_manager::HostedDevicePointerRegistration>> = const { Cell::new(None) };
    static PUBLICATION_PIN: RefCell<Option<nt_io_manager::HostedDeviceProjectionReference>> = const { RefCell::new(None) };
    static REFUSE_FILE_FREE: Cell<bool> = const { Cell::new(false) };
}

fn io_manager_mut() -> &'static mut IoManager<MockObjectPort> {
    // Only synchronous short borrows in this serial fixture; never across a host callback.
    MANAGER.with(|manager| unsafe {
        let pointer = manager.get();
        assert!(!pointer.is_null());
        &mut *pointer
    })
}

struct ManagerScope;
impl Drop for ManagerScope {
    fn drop(&mut self) { MANAGER.with(|manager| manager.set(core::ptr::null_mut())); }
}

mod hosted_device_allocations {
    pub(super) use super::native::{protect_allocation, protects_allocation, stage_driver_object,
        registration, accepted_registration, record_accepted_registration, admit_retirement,
        admit_retirement_checked, finish_retirement};

    pub(super) fn publish_registration(
        inst: super::DriverInstance,
        registration: nt_io_manager::HostedDevicePointerRegistration,
    ) -> Result<(), nt_status::NtStatus> {
        // Fixture-only refusal after the actual canonical bind succeeded. Retain a real pin so
        // cleanup cannot mistake copied catalog provenance for canonical retirement permission.
        if super::REFUSE_PUBLICATION.with(|refuse| refuse.get()) {
            super::ACCEPTED.with(|accepted| accepted.set(Some(registration)));
            let pin = super::io_manager_mut()
                .retain_hosted_device_projection_reference(registration).unwrap();
            super::PUBLICATION_PIN.with(|held| *held.borrow_mut() = Some(pin));
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        super::native::publish_registration(inst, registration)
    }
}

#[path = "../../../components/ntos-executive/src/hosted_device_publication.rs"]
mod publication;
#[path = "../../../components/ntos-executive/src/hosted_device_retirement.rs"]
mod retirement;

unsafe fn hosted_instance_pool_free_unlocked(inst: DriverInstance, address: u64) -> bool {
    assert_pool_locked(inst.exec_pool_va);
    if address == ADDRESS && REFUSE_FILE_FREE.with(|refuse| refuse.get()) {
        return false;
    }
    if hosted_instance_pool_allocation_is_free_unlocked(inst, address) != Some(false) {
        return false;
    }
    let Some((exec, _)) = hosted_pool_allocation_exec_range(inst.exec_pool_va, address) else { return false; };
    let head = (inst.exec_pool_va + 8) as *mut u64;
    write_volatile((exec - 8) as *mut u64, read_volatile(head));
    write_volatile(head, address);
    EVENTS.with(|events| events.borrow_mut().push("free"));
    true
}

fn yield_now() {
    panic!("unexpected native catalog contention/reentry in serial fixture");
}

struct ExecutivePoolLockGuard(u64);
impl Drop for ExecutivePoolLockGuard {
    fn drop(&mut self) {
        POOL_LOCK.with(|lock| {
            assert_eq!(lock.replace(None), Some(self.0));
        });
        EVENTS.with(|events| events.borrow_mut().push("unlock"));
    }
}
fn hosted_instance_pool_lock(exec: u64) -> Option<ExecutivePoolLockGuard> {
    POOL_LOCK.with(|lock| {
        assert_eq!(lock.get(), None, "pool lock acquired recursively");
        lock.set(Some(exec));
    });
    EVENTS.with(|events| events.borrow_mut().push("lock"));
    Some(ExecutivePoolLockGuard(exec))
}
fn assert_pool_locked(exec: u64) {
    POOL_LOCK.with(|lock| assert_eq!(lock.get(), Some(exec)));
}

unsafe fn hosted_instance_pool_allocation_is_free_unlocked(
    inst: DriverInstance, address: u64,
) -> Option<bool> {
    assert_pool_locked(inst.exec_pool_va);
    let mut next = read_volatile((inst.exec_pool_va + 8) as *const u64);
    for _ in 0..16 {
        if next == 0 { return Some(false); }
        if next == address { return Some(true); }
        let offset = next.checked_sub(FSD_POOL_VADDR)?;
        if offset < PAYLOAD || offset >= FSD_POOL_FRAMES * 0x1000 { return None; }
        next = read_volatile((inst.exec_pool_va + offset - 8) as *const u64);
    }
    None
}

unsafe fn hosted_pool_allocation_exec_range(exec: u64, address: u64) -> Option<(u64, u64)> {
    assert_pool_locked(exec);
    let found = nt_io_manager::hosted_pool_range::walk_hosted_pool_allocation(
        FSD_POOL_FRAMES * 0x1000,
        read_volatile(exec as *const u64), POOL_DATA_OFF,
        address.checked_sub(FSD_POOL_VADDR)?, 1,
        |header| Some(read_volatile((exec + header) as *const u64)),
    )?;
    (found.base == address - FSD_POOL_VADDR).then_some((exec + found.base, found.capacity))
}

#[path = "../../../components/ntos-executive/src/hosted_device_allocations.rs"]
mod native;

struct Pool {
    _bytes: Box<[u64]>,
    inst: DriverInstance,
}
impl Pool {
    fn new(domain: HostedDomainIdentity, generation: u64, physical: u64) -> Self {
        let mut bytes = vec![0u64; (FSD_POOL_FRAMES * 0x1000 / 8) as usize].into_boxed_slice();
        bytes[0] = PAYLOAD + CAPACITY;
        bytes[(POOL_DATA_OFF / 8) as usize] = CAPACITY;
        bytes[(POOL_DATA_OFF / 8 + 1) as usize] = generation;
        let inst = DriverInstance {
            used: true,
            exec_pool_va: bytes.as_mut_ptr() as u64,
            pool_frame_base: physical, pml4: physical + 1, domain,
        };
        Self { _bytes: bytes, inst }
    }
    unsafe fn set_generation(&self, generation: u64) {
        let _lock = hosted_instance_pool_lock(self.inst.exec_pool_va).unwrap();
        write_volatile((self.inst.exec_pool_va + PAYLOAD - 8) as *mut u64, generation);
    }
    /// Mock the native allocator's exact free-list effect, not its authority policy.
    unsafe fn free_locked(&self, acknowledged: bool) -> bool {
        assert_pool_locked(self.inst.exec_pool_va);
        if !acknowledged { return false; }
        let head = (self.inst.exec_pool_va + 8) as *mut u64;
        write_volatile((self.inst.exec_pool_va + PAYLOAD - 8) as *mut u64, read_volatile(head));
        write_volatile(head, ADDRESS);
        EVENTS.with(|events| events.borrow_mut().push("free"));
        true
    }
}

unsafe fn populate_device_driver_list(pool: &Pool) -> u64 {
    let exec = pool.inst.exec_pool_va;
    let driver_address = ADDRESS + CAPACITY + 16;
    let driver_exec = exec + PAYLOAD + CAPACITY + 16;
    write_volatile(exec as *mut u64, PAYLOAD + CAPACITY + 16 + 0x200);
    write_volatile((driver_exec - 16) as *mut u64, 0x200);
    write_volatile((driver_exec - 8) as *mut u64, 1);
    write_unaligned(driver_exec as *mut i16, WDM_X64_IO_TYPE_DRIVER);
    write_unaligned((driver_exec + 8) as *mut u64, ADDRESS);
    let device_exec = exec + PAYLOAD;
    write_unaligned(device_exec as *mut i16, WDM_X64_IO_TYPE_DEVICE);
    write_unaligned((device_exec + 2) as *mut u16, WDM_X64_DEVICE_OBJECT_SIZE as u16);
    write_unaligned((device_exec + 8) as *mut u64, driver_address);
    driver_address
}

#[test]
fn actual_file_broker_frees_constructor_name_after_driver_replaces_field() {
    let _serial = TEST_LOCK.lock().unwrap();
    let domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId::new(901, 1),
        cookie: 901,
    };
    let pool = Pool::new(domain, 17, 0x901000);
    let name_a = ADDRESS + CAPACITY + 16;
    let name_b = name_a + 0x100 + 16;
    unsafe {
        let exec = pool.inst.exec_pool_va;
        write_volatile((exec + PAYLOAD + CAPACITY) as *mut u64, 0x100);
        write_volatile((exec + PAYLOAD + CAPACITY + 8) as *mut u64, 18);
        write_volatile((exec + PAYLOAD + CAPACITY + 0x110) as *mut u64, 0x100);
        write_volatile((exec + PAYLOAD + CAPACITY + 0x118) as *mut u64, 19);
        write_volatile(exec as *mut u64, PAYLOAD + CAPACITY + 0x220);
        write_unaligned((exec + PAYLOAD + 0x60) as *mut u64, name_a);
        assert_eq!(native::file_storage_bound_generation(pool.inst, 41, ADDRESS), None);
        native::protect_file_storage(pool.inst, 41, ADDRESS).unwrap();
        let collision = native::protect_file_storage(pool.inst, 41, ADDRESS).err().unwrap();
        assert!(!collision.no_root_owner);
        assert!(native::cancel_unpublished_file_capture(pool.inst, 41, ADDRESS));
        drop(native::generic_free_admission(pool.inst, ADDRESS).unwrap());
        native::protect_file_storage(pool.inst, 41, ADDRESS).unwrap();
        assert_eq!(native::file_storage_bound_generation(pool.inst, 41, ADDRESS), None);
        assert_eq!(native::file_storage_bound_generation(pool.inst, 41, ADDRESS), None);
        assert!(!native::mark_file_unbound_exact(pool.inst, 41, ADDRESS, 7));
        assert_eq!(native::retire_file_storage(pool.inst, 41, ADDRESS),
            Err(nt_status::NtStatus::DEVICE_BUSY));
        assert!(native::mark_file_bound(pool.inst, 41, ADDRESS, 7));
        assert_eq!(native::file_storage_bound_generation(pool.inst, 41, ADDRESS), Some(7));
        assert!(!native::mark_file_unbound_exact(pool.inst, 41, ADDRESS, 6));
        assert_eq!(native::retire_file_storage(pool.inst, 41, ADDRESS),
            Err(nt_status::NtStatus::DEVICE_BUSY));
        write_unaligned((exec + PAYLOAD + 0x60) as *mut u64, name_b);
        assert!(native::generic_free_admission(pool.inst, name_a).is_err());
        assert!(native::generic_free_admission(pool.inst, ADDRESS).is_err());
        drop(native::generic_free_admission(pool.inst, name_b).unwrap());
        assert!(native::mark_file_unbound_exact(pool.inst, 41, ADDRESS, 7));
        REFUSE_FILE_FREE.with(|refuse| refuse.set(true));
        assert_eq!(native::retire_file_storage(pool.inst, 41, ADDRESS),
            Err(nt_status::NtStatus::INVALID_HANDLE));
        REFUSE_FILE_FREE.with(|refuse| refuse.set(false));
        drop(native::generic_free_admission(pool.inst, name_a).unwrap());
        assert!(native::generic_free_admission(pool.inst, ADDRESS).is_err());
        native::retire_file_storage(pool.inst, 41, ADDRESS).unwrap();
        let _lock = hosted_instance_pool_lock(exec).unwrap();
        assert_eq!(hosted_instance_pool_allocation_is_free_unlocked(pool.inst, name_a), Some(true));
        assert_eq!(hosted_instance_pool_allocation_is_free_unlocked(pool.inst, ADDRESS), Some(true));
        assert_eq!(hosted_instance_pool_allocation_is_free_unlocked(pool.inst, name_b), Some(false));
    }
    let refused = unsafe { native::protect_file_storage(pool.inst, 41, ADDRESS) }.err().unwrap();
    assert!(refused.no_root_owner);
}

#[test]
fn actual_adapter_protects_exact_allocations_and_retains_uncertain_retirement() {
    let _serial = TEST_LOCK.lock().unwrap();
    // One scenario owns the real adapter's process-global catalog and all backing pools.
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(
        &NtPath::parse_str(r"\Driver\PoolAdapter").unwrap(),
        Box::new(MockDriverBackend::new()),
    ).unwrap();
    let device = io.create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let logical = io.register_hosted_domain();
    let physical = io.register_hosted_domain();
    let registration = io.bind_hosted_device_pointer(logical, ADDRESS, device).unwrap();
    let pool = Pool::new(physical, 7, 0x1000);
    unsafe {
        let bump = pool.inst.exec_pool_va as *mut u64;
        write_volatile(bump, FSD_POOL_FRAMES * 0x1000 + 8);
        assert_eq!(native::capture_allocation(pool.inst, ADDRESS),
            Err(nt_status::NtStatus::INVALID_PARAMETER));
        write_volatile(bump, PAYLOAD + CAPACITY);
        let unused = DriverInstance { used: false, ..pool.inst };
        assert_eq!(native::capture_allocation(unused, ADDRESS),
            Err(nt_status::NtStatus::ACCESS_DENIED));
        // Plausible header words inside a payload cannot create allocation authority.
        write_volatile((pool.inst.exec_pool_va + PAYLOAD + 16) as *mut u64, 0x100);
        write_volatile((pool.inst.exec_pool_va + PAYLOAD + 24) as *mut u64, 99);
        assert_eq!(native::protect_allocation(pool.inst, ADDRESS + 32),
            Err(nt_status::NtStatus::INVALID_PARAMETER));
        assert!(native::instance_quiesced(pool.inst));
        drop(native::generic_free_admission(pool.inst, ADDRESS).unwrap());
        native::protect_allocation(pool.inst, ADDRESS).unwrap();
        assert!(native::generic_free_admission(pool.inst, ADDRESS).is_err());
        assert!(native::generic_free_admission(pool.inst, ADDRESS + CAPACITY - 1).is_err());
        populate_device_driver_list(&pool);
        native::stage_driver_object(pool.inst, ADDRESS).unwrap();
        native::record_accepted_registration(pool.inst, registration).unwrap();
        native::publish_registration(pool.inst, registration).unwrap();
        assert!(native::generic_free_admission(pool.inst, ADDRESS).is_err());

        let captured = native::capture_allocation(pool.inst, ADDRESS).unwrap();
        pool.set_generation(8);
        assert_eq!(native::protect_allocation_exact(pool.inst, ADDRESS, Some(captured)),
            Err(nt_status::NtStatus::INVALID_PARAMETER));
        assert!(native::admit_retirement(pool.inst, ADDRESS, Some(registration)).is_err());
        assert!(native::protects_allocation(pool.inst, ADDRESS));
        pool.set_generation(7);
        assert!(native::admit_retirement(pool.inst, ADDRESS, None).is_err());

        // The adapter's registration observation is not canonical teardown permission.
        // Drain the real projection and canonical Device before the trusted free effect.
        io.retire_hosted_device_pointer(registration).unwrap();
        io.destroy_device(device).unwrap();

        EVENTS.with(|events| events.borrow_mut().clear());
        let retirement = native::admit_retirement(pool.inst, ADDRESS, Some(registration)).unwrap();
        assert!(pool.free_locked(true));
        // The actual adapter ACK executes while its original pool lock is still held.
        native::finish_retirement(retirement).unwrap();
        EVENTS.with(|events| assert_eq!(&*events.borrow(), &["lock", "free", "unlock"]));
        assert!(native::instance_quiesced(pool.inst));
        drop(native::generic_free_admission(pool.inst, ADDRESS).unwrap());

        let uncertain_domain = io.register_hosted_domain();
        let uncertain = Pool::new(uncertain_domain, 11, 0x2000);
        native::protect_allocation(uncertain.inst, ADDRESS).unwrap();
        let before = uncertain._bytes.to_vec();
        let retirement = native::admit_retirement(uncertain.inst, ADDRESS, None).unwrap();
        assert!(!uncertain.free_locked(false));
        drop(retirement); // Refused/uncertain effect: no ACK, no replay authority.
        assert_eq!(&*uncertain._bytes, before.as_slice());
        assert!(native::protects_allocation(uncertain.inst, ADDRESS));
        assert!(!native::instance_quiesced(uncertain.inst));
        assert!(native::generic_free_admission(uncertain.inst, ADDRESS).is_err());
        assert!(native::admit_retirement(uncertain.inst, ADDRESS, None).is_err());
        assert_eq!(&*uncertain._bytes, before.as_slice());

        // A distinct real physical arena can own the same component numeric address.
        let foreign_domain = io.register_hosted_domain();
        let foreign = Pool::new(foreign_domain, 11, 0x3000);
        drop(native::generic_free_admission(foreign.inst, ADDRESS).unwrap());
        native::protect_allocation(foreign.inst, ADDRESS).unwrap();
        let retirement = native::admit_retirement(foreign.inst, ADDRESS, None).unwrap();
        assert!(foreign.free_locked(true));
        native::finish_retirement(retirement).unwrap();
        assert!(native::instance_quiesced(foreign.inst));
        assert!(native::protects_allocation(uncertain.inst, ADDRESS));

        // A private graph member may be freed only with the allocation captured at creation.
        // A reused address with a new pool generation cannot acknowledge the old owner.
        let member_domain = io.register_hosted_domain();
        let member = Pool::new(member_domain, 17, 0x7000);
        let captured = native::capture_allocation(member.inst, ADDRESS).unwrap();
        member.set_generation(18);
        assert!(!native::free_captured_allocation(member.inst, captured));
        {
            let _pool = hosted_instance_pool_lock(member.inst.exec_pool_va).unwrap();
            assert_eq!(hosted_instance_pool_allocation_is_free_unlocked(member.inst, ADDRESS), Some(false));
        }
        member.set_generation(17);
        assert!(native::free_captured_allocation(member.inst, captured));
        assert!(!native::free_captured_allocation(member.inst, captured));
        // Leak only uncertain backing: actual retained catalog authority must not outlive it.
        std::mem::forget(uncertain);
    }
    MANAGER.with(|manager| manager.set(&mut io));
    let _manager_scope = ManagerScope;
    unsafe { publication_failure_preserves_canonical_owner(driver); }
    unsafe { late_rebind_refuses_actual_physical_retirement(driver); }
    unsafe { malformed_device_preflight_does_not_enter_retirement(); }
    unsafe { stale_registration_cannot_retire_new_unregistered_storage(driver); }
    unsafe { cleared_driver_pointer_cannot_leave_a_freed_device_in_the_driver_list(driver); }
}

unsafe fn cleared_driver_pointer_cannot_leave_a_freed_device_in_the_driver_list(
    driver: nt_io_manager::DriverId,
) {
    let device = io_manager_mut().create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let domain = io_manager_mut().register_hosted_domain();
    let physical = io_manager_mut().register_hosted_domain();
    let pool = Pool::new(physical, 67, 0xa000);
    let exec = pool.inst.exec_pool_va;
    let device_exec = exec + PAYLOAD;
    let driver_address = ADDRESS + CAPACITY + 16;
    let driver_exec = exec + PAYLOAD + CAPACITY + 16;
    write_volatile(exec as *mut u64, PAYLOAD + CAPACITY + 16 + 0x200);
    write_volatile((driver_exec - 8) as *mut u64, 68);
    write_volatile((driver_exec - 16) as *mut u64, 0x200);
    write_unaligned(driver_exec as *mut i16, WDM_X64_IO_TYPE_DRIVER);
    write_unaligned((driver_exec + 8) as *mut u64, ADDRESS);
    write_unaligned(device_exec as *mut i16, WDM_X64_IO_TYPE_DEVICE);
    write_unaligned((device_exec + 2) as *mut u16, WDM_X64_DEVICE_OBJECT_SIZE as u16);
    write_unaligned((device_exec + 8) as *mut u64, driver_address);
    native::protect_allocation(pool.inst, ADDRESS).unwrap();
    write_unaligned((device_exec + 8) as *mut u64, 0);
    assert_eq!(native::stage_driver_object(pool.inst, ADDRESS),
        Err(nt_status::NtStatus::INVALID_PARAMETER));
    write_unaligned((device_exec + 8) as *mut u64, driver_address);
    native::stage_driver_object(pool.inst, ADDRESS).unwrap();
    let registration = io_manager_mut().bind_hosted_device_pointer(domain, ADDRESS, device).unwrap();
    native::record_accepted_registration(pool.inst, registration).unwrap();
    io_manager_mut().retire_hosted_device_pointer(registration).unwrap();
    io_manager_mut().destroy_device(device).unwrap();

    // The provider can mutate the projected header. It cannot thereby erase the original
    // driver's live DeviceObject list link and grant physical-free authority.
    write_unaligned((device_exec + 8) as *mut u64, 0);
    let before = pool._bytes.to_vec();
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration }, None),
        Err(nt_status::NtStatus::INVALID_PARAMETER));
    assert_eq!(&*pool._bytes, before.as_slice());
    assert!(native::protects_allocation(pool.inst, ADDRESS));
    write_unaligned((device_exec + 8) as *mut u64, driver_address);
    retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration }, None).unwrap();
    assert_eq!(read_unaligned((driver_exec + 8) as *const u64), 0);
    assert!(native::instance_quiesced(pool.inst));
}

unsafe fn stale_registration_cannot_retire_new_unregistered_storage(
    driver: nt_io_manager::DriverId,
) {
    let device = io_manager_mut().create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let logical = io_manager_mut().register_hosted_domain();
    let stale = io_manager_mut().bind_hosted_device_pointer(logical, ADDRESS, device).unwrap();
    io_manager_mut().retire_hosted_device_pointer(stale).unwrap();
    io_manager_mut().destroy_device(device).unwrap();

    let physical = io_manager_mut().register_hosted_domain();
    let pool = Pool::new(physical, 61, 0x9000);
    let device_exec = pool.inst.exec_pool_va + PAYLOAD;
    write_unaligned(device_exec as *mut i16, WDM_X64_IO_TYPE_DEVICE);
    write_unaligned((device_exec + 2) as *mut u16, WDM_X64_DEVICE_OBJECT_SIZE as u16);
    native::protect_allocation(pool.inst, ADDRESS).unwrap();
    assert_eq!(native::registration(pool.inst, ADDRESS).unwrap(), None);
    let before = pool._bytes.to_vec();
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration: stale }, None),
        Err(nt_status::NtStatus::INVALID_HANDLE));
    assert_eq!(&*pool._bytes, before.as_slice());
    assert!(native::protects_allocation(pool.inst, ADDRESS));
    retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::ConfirmedUnbound { domain: logical }, None).unwrap();
    assert!(native::instance_quiesced(pool.inst));
}

unsafe fn malformed_device_preflight_does_not_enter_retirement() {
    let domain = io_manager_mut().register_hosted_domain();
    let pool = Pool::new(domain, 53, 0x8000);
    native::protect_allocation(pool.inst, ADDRESS).unwrap();
    let device_exec = pool.inst.exec_pool_va + PAYLOAD;
    write_unaligned(device_exec as *mut i16, WDM_X64_IO_TYPE_DEVICE);
    write_unaligned((device_exec + 2) as *mut u16, 0);
    let before = pool._bytes.to_vec();
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::ConfirmedUnbound { domain }, None),
        Err(nt_status::NtStatus::INVALID_PARAMETER));
    assert_eq!(&*pool._bytes, before.as_slice(), "rejected preflight has no native effect");
    assert!(native::protects_allocation(pool.inst, ADDRESS));
    write_unaligned((device_exec + 2) as *mut u16, WDM_X64_DEVICE_OBJECT_SIZE as u16);
    retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::ConfirmedUnbound { domain }, None)
        .expect("no-effect preflight refusal preserves exact retirement authority");
    assert!(native::instance_quiesced(pool.inst));
}

unsafe fn late_rebind_refuses_actual_physical_retirement(driver: nt_io_manager::DriverId) {
    let device = io_manager_mut().create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let domain = io_manager_mut().register_hosted_domain();
    let physical = io_manager_mut().register_hosted_domain();
    assert_ne!(domain, physical);
    let pool = Pool::new(physical, 43, 0x6000);
    populate_device_driver_list(&pool);
    native::protect_allocation(pool.inst, ADDRESS).unwrap();
    let original = io_manager_mut().bind_hosted_device_pointer(domain, ADDRESS, device).unwrap();
    // Model accepted bind followed by refused catalog publication: the physical owner still
    // records the exact accepted token before the later attach can fail.
    native::stage_driver_object(pool.inst, ADDRESS).unwrap();
    native::record_accepted_registration(pool.inst, original).unwrap();
    assert_eq!(native::registration(pool.inst, ADDRESS).unwrap(), None);
    assert_eq!(native::accepted_registration(pool.inst, ADDRESS).unwrap(), Some(original));
    io_manager_mut().retire_hosted_device_pointer(original).unwrap();
    let rebound = io_manager_mut().bind_hosted_device_pointer(domain, ADDRESS, device).unwrap();
    assert_ne!(rebound, original);
    let mut pin = io_manager_mut().retain_hosted_device_projection_reference(rebound).unwrap();
    let before = pool._bytes.to_vec();
    // Old PDO cleanup cleared its canonical token and passed the catalog's None. Execute the
    // actual native helper: a new live registration must refuse before any pool or link stores.
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::ConfirmedUnbound { domain }, None),
        Err(nt_status::NtStatus::DEVICE_BUSY));
    assert_eq!(&*pool._bytes, before.as_slice());
    assert_eq!(io_manager_mut().hosted_device_pointer_registration(domain, ADDRESS), Some(rebound));
    assert!(native::protects_allocation(pool.inst, ADDRESS));
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration: original }, None),
        Err(nt_status::NtStatus::DEVICE_BUSY));
    assert_eq!(&*pool._bytes, before.as_slice());
    io_manager_mut().release_hosted_device_projection_reference(&mut pin).unwrap();
    io_manager_mut().retire_hosted_device_pointer(rebound).unwrap();
    io_manager_mut().bind_hosted_device_identity(domain, ADDRESS, device).unwrap();
    assert_eq!(io_manager_mut().hosted_device_pointer_registration(domain, ADDRESS), None);
    assert_eq!(retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration: original }, None),
        Err(nt_status::NtStatus::DEVICE_BUSY));
    assert_eq!(&*pool._bytes, before.as_slice());
    assert!(io_manager_mut().unbind_hosted_device_identity(domain, ADDRESS, device));
    retirement::retire_hosted_device_projection(pool.inst, ADDRESS,
        retirement::CanonicalRetirement::Retired { registration: original }, None).unwrap();
    io_manager_mut().destroy_device(device).unwrap();
    assert!(native::instance_quiesced(pool.inst));
}

unsafe fn publication_failure_preserves_canonical_owner(driver: nt_io_manager::DriverId) {
    let first = io_manager_mut().create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let other = io_manager_mut().create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let existing_domain = io_manager_mut().register_hosted_domain();
    let existing = Pool::new(existing_domain, 31, 0x4000);
    populate_device_driver_list(&existing);
    let registration = match publication::register_hosted_device_projection(
        existing.inst, existing_domain, ADDRESS, first,
    ) {
        Ok(registration) => registration,
        Err(_) => panic!("valid initial publication must succeed"),
    };
    let pin = io_manager_mut().retain_hosted_device_projection_reference(registration).unwrap();
    let before = existing._bytes.to_vec();
    let error = match publication::register_hosted_device_projection(
        existing.inst, existing_domain, ADDRESS, other,
    ) {
        Ok(_) => panic!("foreign Device must not replace existing registration"),
        Err(error) => error,
    };
    assert!(error.retained);
    assert_eq!(error.accepted_registration(), None);
    assert!(!error.cleanup_unbound);
    assert_eq!(io_manager_mut().hosted_device_pointer_registration(existing_domain, ADDRESS), Some(registration));
    assert_eq!(io_manager_mut().retire_hosted_device_pointer(registration), Err(nt_status::NtStatus::DEVICE_BUSY));
    assert_eq!(&*existing._bytes, before.as_slice());
    assert!(native::generic_free_admission(existing.inst, ADDRESS).is_err());
    let mut pin = pin;
    io_manager_mut().release_hosted_device_projection_reference(&mut pin).unwrap();
    io_manager_mut().retire_hosted_device_pointer(registration).unwrap();
    io_manager_mut().destroy_device(first).unwrap();
    let retirement = native::admit_retirement(existing.inst, ADDRESS, Some(registration)).unwrap();
    assert!(existing.free_locked(true));
    native::finish_retirement(retirement).unwrap();

    let failed_domain = io_manager_mut().register_hosted_domain();
    let failed = Pool::new(failed_domain, 37, 0x5000);
    populate_device_driver_list(&failed);
    let before = failed._bytes.to_vec();
    REFUSE_PUBLICATION.with(|refuse| refuse.set(true));
    let result = publication::register_hosted_device_projection(failed.inst, failed_domain, ADDRESS, other);
    REFUSE_PUBLICATION.with(|refuse| refuse.set(false));
    let error = match result {
        Ok(_) => panic!("injected post-bind publication refusal must be observed"),
        Err(error) => error,
    };
    let accepted = ACCEPTED.with(|accepted| accepted.get()).expect("actual publish callback saw minted bind token");
    assert_eq!(error.status, nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    assert!(error.retained);
    assert_eq!(io_manager_mut().hosted_device_pointer_registration(failed_domain, ADDRESS), Some(accepted));
    assert_eq!(io_manager_mut().retire_hosted_device_pointer(accepted), Err(nt_status::NtStatus::DEVICE_BUSY));
    assert_eq!(&*failed._bytes, before.as_slice());
    assert!(native::generic_free_admission(failed.inst, ADDRESS).is_err());
    // The exact accepted bind survives refusal; only its owner may retire it.
    assert_eq!(error.accepted_registration(), Some(accepted));
    assert!(!error.cleanup_unbound);
    let accepted = error.accepted_registration().expect("retained bind owner provenance");

    let mut pin = PUBLICATION_PIN.with(|held| held.borrow_mut().take()).unwrap();
    io_manager_mut().release_hosted_device_projection_reference(&mut pin).unwrap();
    io_manager_mut().retire_hosted_device_pointer(accepted).unwrap();
    io_manager_mut().destroy_device(other).unwrap();
    // Physical publication never completed, but the physical owner retained the accepted
    // canonical token. Retirement attaches that token under the same checked exclusion.
    assert_eq!(native::registration(failed.inst, ADDRESS).unwrap(), None);
    assert_eq!(native::accepted_registration(failed.inst, ADDRESS).unwrap(), Some(accepted));
    let retirement = native::admit_retirement(failed.inst, ADDRESS, Some(accepted)).unwrap();
    assert!(failed.free_locked(true));
    native::finish_retirement(retirement).unwrap();
}
