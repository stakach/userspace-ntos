//! Test identities minted by the real I/O Manager, plus isolated allocator refusal.
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, DriverId, HostedDevicePointerRegistration,
    HostedDomainId, HostedDomainIdentity, IoManager, MockDriverBackend, MockObjectPort,
};
use nt_pnp_manager::returned_pnp_buffer::{
    BufferOrigin, PhysicalPoolArena, ReturnedAllocation, ReturnedPnpQuery, ReturnedPnpRequest,
};
use nt_types::NtPath;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) const SUCCESS: u32 = 0;
pub(super) const PENDING: u32 = 0x103;
pub(super) const NOT_SUPPORTED: u32 = 0xc00000bb;
pub(super) const ALLOCATION_CHILD: &str = "NT_RETURNED_PNP_BUFFER_ALLOCATION_CHILD";

struct RefusingAllocator;
pub(super) static REFUSE: AtomicBool = AtomicBool::new(false);
pub(super) static REQUESTS: AtomicUsize = AtomicUsize::new(0);

// Like the hive allocation tests, refusal is armed only in a dedicated current_exe child.
// SAFETY: refusal returns null without touching allocations; all other operations delegate to System.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE.load(Ordering::Relaxed) {
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplied the allocator layout unchanged.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if REFUSE.load(Ordering::Relaxed) {
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplied the allocator layout unchanged.
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if REFUSE.load(Ordering::Relaxed) {
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplied the live allocation and replacement size unchanged.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: successful allocations came from System with this same layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;

pub(super) fn domain(id: u64, cookie: u64) -> HostedDomainIdentity {
    HostedDomainIdentity {
        domain_id: HostedDomainId::new(1, id),
        cookie,
    }
}

fn arena() -> PhysicalPoolArena {
    PhysicalPoolArena {
        domain: domain(9, 90),
        pml4: 0x1000,
        pool_frame_base: 0x2000,
        exec_pool_va: 0x100000,
    }
}

pub(super) fn source() -> SourceIrpAllocation {
    SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(3),
        domain: domain(3, 30),
        component_address: 0x400000,
        bytes: 1024,
        stack_count: 2,
        pool_generation: 11,
    }
}

pub(super) struct TargetFixture {
    pub(super) io: IoManager<MockObjectPort>,
    driver: DriverId,
    pub(super) target: HostedDevicePointerRegistration,
}

impl TargetFixture {
    pub(super) fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ReturnedPnpTarget").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let domain = io.register_hosted_domain();
        let target = io
            .bind_hosted_device_pointer(domain, 0x600000, device)
            .unwrap();
        Self { io, driver, target }
    }

    pub(super) fn another_device(
        &mut self,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> HostedDevicePointerRegistration {
        let device = self
            .io
            .create_device(
                self.driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        self.io
            .bind_hosted_device_pointer(domain, address, device)
            .unwrap()
    }
}

std::thread_local! {
    // Keep the minting manager alive throughout each test; the observation itself owns no pin.
    static TARGET: std::cell::RefCell<Option<TargetFixture>> = const { std::cell::RefCell::new(None) };
}

fn target() -> HostedDevicePointerRegistration {
    TARGET.with(|slot| {
        slot.borrow_mut()
            .get_or_insert_with(TargetFixture::new)
            .target
    })
}

pub(super) fn request() -> ReturnedPnpRequest {
    let source = source();
    ReturnedPnpRequest {
        source_ticket: SourceIrpTicket::new(source.domain, 17, 7).unwrap(),
        source,
        source_arena: PhysicalPoolArena {
            domain: source.domain,
            ..arena()
        },
        expected_allocator: arena(),
        parent_devnode: 41,
        parent_generation: 2,
        target: target(),
        canonical_irp_id: 51,
        query: ReturnedPnpQuery::DeviceText {
            text_type: 0,
            locale_id: 0x409,
        },
    }
}

pub(super) fn allocation() -> ReturnedAllocation {
    ReturnedAllocation {
        arena: arena(),
        pool: SourcePoolAllocationIdentity {
            component_address: 0x500000,
            capacity: 64,
            pool_generation: 21,
        },
        origin: BufferOrigin::IndependentPool,
    }
}

pub(super) fn other_request() -> ReturnedPnpRequest {
    let original = request();
    ReturnedPnpRequest {
        source_ticket: SourceIrpTicket::new(original.source.domain, 18, 8).unwrap(),
        source: SourceIrpAllocation {
            component_address: original.source.component_address + 0x1000,
            pool_generation: original.source.pool_generation + 1,
            ..original.source
        },
        canonical_irp_id: original.canonical_irp_id + 1,
        ..original
    }
}
