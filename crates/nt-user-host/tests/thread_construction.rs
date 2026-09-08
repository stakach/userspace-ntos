use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::thread_binding::{
    admit_thread_binding, ThreadBinding, ThreadRuntimeReservations,
};
use nt_user_host::thread_construction::{
    Role as ConstructionRole, SlotState, ThreadConstructionInventory,
};
use nt_user_host::thread_publication::{
    PreparedThreadPublication, PublicationError, ThreadPublicationSlot,
};
use nt_user_host::thread_resources::{ThreadMemoryLayout, ThreadMemoryResources};
use nt_user_host::thread_retirement::{Operation, RetirementError, ThreadRetirementIo};
use nt_user_host::thread_rollback::{
    ThreadRollbackError, ThreadRollbackId, ThreadRollbackIo, ThreadRollbackResource,
    ThreadRollbackResourceKind as Kind, ThreadRollbackStage,
};
use nt_user_host::thread_slot::{
    RuntimeConstruction, RuntimeIdentity, SlotError, ThreadIngressError, ThreadRuntimeSlot,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::rc::Rc;

#[path = "thread_construction/failed_memory_slot.rs"]
mod failed_memory_slot;

#[path = "thread_construction/alias_journal.rs"]
mod alias_journal;

#[path = "thread_construction/frame_recycle.rs"]
mod frame_recycle;

#[path = "thread_construction/prefetch_journal.rs"]
mod prefetch_journal;

#[path = "thread_construction/section_scratch.rs"]
mod section_scratch;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static FAIL_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn count_allocation() {
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        if FAIL_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) { return std::ptr::null_mut(); }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        if FAIL_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) { return std::ptr::null_mut(); }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        if FAIL_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) { return std::ptr::null_mut(); }
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn without_allocation<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNTING.with(|flag| flag.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|flag| assert!(!flag.replace(true)));
    let reset = Reset;
    let result = f();
    drop(reset);
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    result
}

#[derive(Debug)]
struct Partial {
    binding: ThreadBinding<u32>,
    tcb: Option<u64>,
    memory: ThreadMemoryResources<2>,
    mechanisms: Vec<ThreadRollbackResource>,
    inventory: ThreadConstructionInventory,
    memory_progress: nt_user_host::thread_construction::MemoryConstructionProgress<2>,
    drops: Rc<Cell<usize>>,
}

impl Drop for Partial {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[derive(Debug)]
struct Runtime {
    binding: ThreadBinding<u32>,
    publication: ThreadPublicationSlot,
    partial: Option<Partial>,
    reconciliation: nt_user_host::thread_reconciliation::ThreadRegistryReconciliation<2>,
    coverage: nt_user_host::thread_construction::MemoryConstructionCoverage<2>,
    projection_override: Option<u64>,
}

impl RuntimeIdentity for Runtime {
    type Role = u32;
    fn binding(&self) -> ThreadBinding<u32> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}

impl RuntimeConstruction for Runtime {
    type Partial = Partial;
    fn construction_binding(partial: &Partial) -> ThreadBinding<u32> {
        partial.binding
    }
    fn construction_tcb(partial: &Partial) -> Option<u64> {
        partial.tcb
    }
    fn validate_construction(partial: &Partial) -> Result<(), ThreadRollbackError> {
        partial.memory_progress.validate_failed_slot(&partial.inventory, &partial.memory)
    }
    fn publication_mut(&mut self) -> &mut ThreadPublicationSlot {
        &mut self.publication
    }
    fn clear_retired_tcb_projection(&mut self, expected_cap: u64) -> Result<(), u32> {
        if self.binding.tcb != expected_cap && self.binding.tcb != 1 {
            return Err(0xc000_000d);
        }
        self.binding.tcb = 1;
        Ok(())
    }
    fn retain_partial(&mut self, mut partial: Partial) -> (ThreadConstructionInventory, Option<nt_user_host::thread_construction::FailedMemorySlot>) {
        assert!(self.partial.is_none());
        self.binding.tcb = self.projection_override.unwrap_or(partial.tcb.unwrap_or(1));
        let inventory = std::mem::replace(&mut partial.inventory, ThreadConstructionInventory::empty());
        let progress = std::mem::replace(&mut partial.memory_progress, nt_user_host::thread_construction::MemoryConstructionProgress::empty());
        let (coverage, memory_slot) = progress.into_retained();
        self.coverage = coverage;
        self.partial = Some(partial);
        (inventory, memory_slot)
    }
}

type Slot = ThreadRuntimeSlot<Runtime>;
type Ticket = PreparedThreadPublication<ThreadBinding<u32>>;

fn fixture(tcb: Option<u64>, built: bool) -> (Slot, Ticket, Partial, Rc<Cell<usize>>) {
    let binding = ThreadBinding {
        pi: 2,
        tid: 24,
        badge: 4,
        role: 1,
        tcb: 1,
        process: ProcessIdentity {
            pid: 8,
            generation: ProcessGeneration::Hosted(7),
        },
        reservations: Some(ThreadRuntimeReservations {
            badge: 4,
            pool_slot: 3,
            window_slot: Some(5),
        }),
    };
    let mut slot = Slot::empty();
    slot.insert(Runtime {
        binding,
        publication: ThreadPublicationSlot::empty(),
        partial: None,
        reconciliation: nt_user_host::thread_reconciliation::ThreadRegistryReconciliation::empty(),
        coverage: nt_user_host::thread_construction::MemoryConstructionCoverage::empty(),
        projection_override: None,
    })
    .unwrap();
    let ticket = slot
        .ordinary_mut()
        .unwrap()
        .publication
        .prepare(binding)
        .unwrap();
    let mut memory = ThreadMemoryResources::new(
        2,
        ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x5000, 0x8000).unwrap(),
    )
    .unwrap();
    if built {
        memory.stack_owner[0] = 200;
        memory.stack_target[0] = 100;
    }
    let drops = Rc::new(Cell::new(0));
    let mut inventory = ThreadConstructionInventory::empty();
    if let Some(cap) = tcb.filter(|&cap| cap > 1) {
        inventory.adopt_object(ConstructionRole::Tcb, cap).unwrap();
    }
    let partial = Partial {
        binding,
        tcb,
        memory,
        mechanisms: if built {
            vec![ThreadRollbackResource {
                cap: 300,
                kind: Kind::Mechanism,
            }]
        } else {
            vec![]
        },
        drops: drops.clone(),
        inventory,
        memory_progress: nt_user_host::thread_construction::MemoryConstructionProgress::empty(),
    };
    (slot, ticket, partial, drops)
}

fn assert_protected(slot: &mut Slot, id: ThreadRollbackId) {
    let binding = slot.owner().unwrap().binding;
    assert!(slot.is_pending() && slot.is_protected());
    assert!(slot.executable().is_none());
    assert!(slot.ordinary_mut().is_none());
    assert!(slot.releasable().is_none());
    assert!(slot.release_published().is_none());
    assert!(slot.take_retired_payload(id).is_none());
    assert_eq!(
        slot.admit_ingress(binding.badge, Some(binding.process))
            .unwrap_err(),
        ThreadIngressError::Pending
    );
    assert!(binding.holds_pool_slot(2, 3) && binding.holds_window_slot(2, 5));
}

#[test]
fn registry_preparation_oom_and_revalidation_keep_pending_ownership() {
    use nt_memory_manager::ClientFrameRegistry;
    use nt_user_host::thread_reconciliation::ReconciliationError;
    use nt_user_host::thread_registry::ThreadRegistryError;
    struct ResetAllocationFailure;
    impl Drop for ResetAllocationFailure {
        fn drop(&mut self) { FAIL_ALLOCATIONS.with(|flag| flag.set(false)); }
    }
    let (mut slot, ticket, mut partial, drops) = fixture(None, true);
    partial.memory_progress.record_stack(0);
    partial.memory_progress.retain_empty_slot(601).unwrap();
    let mut registry = ClientFrameRegistry::new();
    registry.insert(2, 0x1000, 200, 0, 201, 202, false).unwrap();
    let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
    {
        let runtime = slot.owner().unwrap();
        let retirement = slot.pending().unwrap().construction_retirement().unwrap();
        let partial = runtime.partial.as_ref().unwrap();
        FAIL_ALLOCATIONS.with(|flag| flag.set(true));
        let reset = ResetAllocationFailure;
        let failure = runtime.reconciliation.reconcile(id, &partial.memory, &runtime.coverage, retirement, &registry);
        drop(reset);
        assert!(matches!(failure, Err(ReconciliationError::Registry(ThreadRegistryError::InsufficientResources))));
        assert!(!runtime.reconciliation.is_prepared());
        runtime.reconciliation.reconcile(id, &partial.memory, &runtime.coverage, retirement, &registry).unwrap();
        without_allocation(|| runtime.reconciliation.reconcile(id, &partial.memory, &runtime.coverage, retirement, &registry)).unwrap();
        registry.take(2, 0x1000).unwrap();
        let result = without_allocation(|| runtime.reconciliation.reconcile(id, &partial.memory, &runtime.coverage, retirement, &registry));
        assert!(matches!(result, Err(ReconciliationError::Registry(ThreadRegistryError::StaleRecord { page: 0x1000 }))));
        assert!(runtime.reconciliation.is_prepared());
    }
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn memory_failure_and_registry_coverage_move_with_original_reservations() {
    for tcb in [None, Some(400)] {
        let (mut slot, ticket, mut partial, drops) = fixture(tcb, true);
        partial.memory_progress.retain_empty_slot(601).unwrap();
        partial.memory_progress.record_stack(0);
        partial.memory_progress.record_teb(1);
        let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
        assert_protected(&mut slot, id);
        let partial = slot.owner().unwrap().partial.as_ref().unwrap();
        let coverage = &slot.owner().unwrap().coverage;
        assert_eq!(coverage.empty_slot(), Some(601));
        assert!(coverage.stack_registered(0));
        assert!(!coverage.stack_registered(1));
        assert!(!coverage.teb_registered(0));
        assert!(coverage.teb_registered(1));
        assert!(partial.memory_progress.is_empty());
        assert_eq!(slot.pending().unwrap().construction_retirement().unwrap().pending_memory_slot(), Some(601));
        assert_eq!(partial.memory.stack_owner[0], 200);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn rejected_handoff_does_not_drop_failed_memory_slot_or_publication_coverage() {
    let (mut slot, ticket, mut partial, drops) = fixture(None, true);
    partial.memory_progress.retain_empty_slot(601).unwrap();
    partial.memory_progress.record_stack(1);
    let (mut wrong, _, _, _) = fixture(None, false);
    let (_, ticket, partial) = without_allocation(|| wrong.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(partial.memory_progress.empty_slot(), Some(601));
    assert!(partial.memory_progress.stack_registered(1));
    assert_eq!(drops.get(), 0);
    let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn actual_slot_inventory_moves_with_memory_and_holds_without_allocation() {
    for state in [
        SlotState::AllocatedEmpty(400),
        SlotState::LiveObject(400),
        SlotState::DeleteAcknowledged(400),
    ] {
        let tcb = matches!(state, SlotState::LiveObject(_)).then_some(400);
        let (mut slot, ticket, mut partial, drops) = fixture(tcb, true);
        partial.inventory = ThreadConstructionInventory::empty();
        partial
            .inventory
            .adopt_object(ConstructionRole::RawCnode, 500)
            .unwrap();
        partial
            .inventory
            .adopt_object(ConstructionRole::GuardedCnode, 501)
            .unwrap();
        partial
            .inventory
            .adopt_empty(ConstructionRole::Tcb, 400)
            .unwrap();
        if state != SlotState::AllocatedEmpty(400) {
            partial
                .inventory
                .acknowledge_object(ConstructionRole::Tcb, 400)
                .unwrap();
        }
        if state == SlotState::DeleteAcknowledged(400) {
            partial
                .inventory
                .acknowledge_delete(ConstructionRole::Tcb, 400)
                .unwrap();
        }
        let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
        assert_protected(&mut slot, id);
        let snapshot = slot.owner().unwrap().binding;
        assert_eq!(snapshot.tcb, tcb.unwrap_or(1));
        let retained = slot.owner().unwrap().partial.as_ref().unwrap();
        assert!(retained.inventory.is_empty());
        let inventory = slot.pending().unwrap().construction_retirement().unwrap().inventory();
        assert_eq!(inventory.state(ConstructionRole::Tcb), state);
        assert_eq!(inventory.live_tcb(), tcb);
        assert_eq!(retained.memory.stack_owner[0], 200);
        assert_eq!(
            inventory.state(ConstructionRole::RawCnode),
            SlotState::LiveObject(500)
        );
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn rejected_handoff_returns_the_real_inventory_and_can_retry() {
    let (mut slot, ticket, mut partial, drops) = fixture(None, true);
    partial
        .inventory
        .adopt_empty(ConstructionRole::Tcb, 400)
        .unwrap();
    partial
        .inventory
        .adopt_object(ConstructionRole::RawCnode, 500)
        .unwrap();
    let (mut wrong, _, _, _) = fixture(None, false);
    let (error, ticket, partial) =
        without_allocation(|| wrong.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(
        error,
        SlotError::Publication(PublicationError::StaleAttempt)
    );
    assert_eq!(
        partial.inventory.state(ConstructionRole::Tcb),
        SlotState::AllocatedEmpty(400)
    );
    assert_eq!(
        partial.inventory.state(ConstructionRole::RawCnode),
        SlotState::LiveObject(500)
    );
    assert_eq!(drops.get(), 0);
    assert!(without_allocation(|| slot.retain_failed_construction(ticket, partial)).is_ok());
}

#[test]
fn empty_construction_handoff_is_allocation_free_and_not_releasable() {
    let (mut slot, ticket, partial, drops) = fixture(None, false);
    let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
    assert_protected(&mut slot, id);
    let owner = slot.owner().unwrap();
    assert_eq!(owner.binding.tcb, 1);
    // This copied metadata alone would incorrectly allow native unbuilt-reservation release.
    assert!(owner.publication.can_release_unbuilt(1, false));
    assert!(slot.pending().unwrap().cleanup().is_none());
    assert_eq!(drops.get(), 0);
}

#[test]
fn partial_handoff_moves_existing_inventory_without_allocation() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let inventory_ptr = partial.mechanisms.as_ptr();
    let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
    assert_protected(&mut slot, id);
    let runtime = slot.owner().unwrap();
    let partial = runtime.partial.as_ref().unwrap();
    assert_eq!(partial.mechanisms.as_ptr(), inventory_ptr);
    assert_eq!(partial.memory.stack_owner, [200, 0]);
    assert_eq!(runtime.binding.tcb, 400);
    let competitor = ThreadBinding {
        tid: 25,
        badge: 5,
        role: 2,
        reservations: None,
        ..runtime.binding
    };
    assert!(admit_thread_binding(competitor, [(0, runtime.binding)]).is_err());
    assert_eq!(drops.get(), 0);
}

#[test]
fn partial_identity_mismatches_return_exact_ticket_and_payload() {
    for field in 0..10 {
        let (mut slot, ticket, mut partial, drops) = fixture(Some(400), true);
        let original = partial.binding;
        match field {
            0 => partial.binding.pi += 1,
            1 => partial.binding.process.pid += 1,
            2 => partial.binding.process.generation = ProcessGeneration::Hosted(8),
            3 => partial.binding.process.generation = ProcessGeneration::Temporary(7),
            4 => partial.binding.tid += 1,
            5 => partial.binding.badge += 1,
            6 => partial.binding.role += 1,
            7 => partial.binding.tcb = 400,
            8 => partial.binding.reservations.as_mut().unwrap().pool_slot += 1,
            _ => partial.binding.reservations.as_mut().unwrap().window_slot = None,
        }
        let ptr = partial.mechanisms.as_ptr();
        let (error, ticket, mut partial) =
            without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap_err();
        assert_eq!(error, SlotError::OwnerChanged);
        assert_eq!(partial.mechanisms.as_ptr(), ptr);
        assert!(slot.publishing_mut(&ticket).is_some());
        assert_eq!(slot.owner().unwrap().binding, original);
        assert_eq!(drops.get(), 0);
        partial.binding = original;
        assert!(slot.retain_failed_construction(ticket, partial).is_ok());
    }
}

#[test]
fn wrong_slot_ticket_cannot_replace_its_owner() {
    let (mut first, ticket, partial, drops) = fixture(None, true);
    let (mut second, second_ticket, second_partial, _) = fixture(None, false);
    let (error, ticket, partial) =
        without_allocation(|| second.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(
        error,
        SlotError::Publication(PublicationError::StaleAttempt)
    );
    assert!(first.publishing_mut(&ticket).is_some());
    assert!(second.publishing_mut(&second_ticket).is_some());
    assert_eq!(drops.get(), 0);
    assert!(first.retain_failed_construction(ticket, partial).is_ok());
    assert!(second
        .retain_failed_construction(second_ticket, second_partial)
        .is_ok());
}

#[test]
fn invalid_tcb_caps_return_ownership_and_never_reach_cleanup() {
    for cap in [0, 1] {
        let (mut slot, ticket, mut partial, drops) = fixture(Some(cap), true);
        let (error, ticket, returned) =
            without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap_err();
        partial = returned;
        assert_eq!(
            error,
            SlotError::Cleanup(ThreadRollbackError::InvalidCapability)
        );
        assert!(slot.publishing_mut(&ticket).is_some());
        assert_eq!(drops.get(), 0);
        partial.tcb = None;
        assert!(slot.retain_failed_construction(ticket, partial).is_ok());
    }
}

#[test]
fn stale_original_row_binding_preserves_busy_ownership() {
    let (mut slot, ticket, partial, drops) = fixture(None, true);
    // Simulate an adapter violating the exclusive publication contract.
    slot.publishing_mut(&ticket)
        .unwrap()
        .binding
        .process
        .generation = ProcessGeneration::Hosted(8);
    let (error, ticket, partial) =
        without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(
        error,
        SlotError::Publication(PublicationError::OwnerChanged)
    );
    assert!(slot.is_protected());
    assert!(slot.release_published().is_none());
    assert_eq!(ticket.owner(), &partial.binding);
    assert_eq!(drops.get(), 0);
}

#[test]
fn vacant_or_pending_destination_returns_owners_without_replacement() {
    let (mut source, ticket, partial, drops) = fixture(None, true);
    let mut empty = Slot::empty();
    let (error, ticket, partial) =
        without_allocation(|| empty.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(error, SlotError::Vacant);
    assert!(empty.is_empty());
    let (mut pending, other_ticket, other_partial, other_drops) = fixture(None, false);
    let id = pending
        .retain_failed_construction(other_ticket, other_partial)
        .unwrap();
    let (error, ticket, partial) =
        without_allocation(|| pending.retain_failed_construction(ticket, partial)).unwrap_err();
    assert_eq!(error, SlotError::AlreadyPending);
    assert_eq!(pending.pending().unwrap().id(), id);
    assert!(source.publishing_mut(&ticket).is_some());
    assert_eq!(drops.get(), 0);
    assert_eq!(other_drops.get(), 0);
    assert!(source.retain_failed_construction(ticket, partial).is_ok());
}

#[test]
fn handoff_requires_unbuilt_reservation_and_captured_holds() {
    for built in [false, true] {
        let (mut slot, ticket, mut partial, drops) = fixture(None, true);
        let runtime = slot.publishing_mut(&ticket).unwrap();
        runtime
            .publication
            .finish(ticket, &runtime.binding)
            .unwrap();
        if built {
            runtime.binding.tcb = 400;
        } else {
            runtime.binding.reservations = None;
        }
        partial.binding = runtime.binding;
        let ticket = runtime.publication.prepare(runtime.binding).unwrap();
        let (error, ticket, partial) =
            without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap_err();
        assert_eq!(
            error,
            if built {
                SlotError::InvalidBinding
            } else {
                SlotError::MissingReservations
            }
        );
        assert!(slot.publishing_mut(&ticket).is_some());
        assert_eq!(ticket.owner(), &partial.binding);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn releasable_projection_matches_ordinary_slot_extraction() {
    let (mut slot, ticket, partial, _) = fixture(None, false);
    assert!(slot.releasable().is_none());
    assert!(slot.release_published().is_none());
    let binding = *ticket.owner();
    slot.publishing_mut(&ticket)
        .unwrap()
        .publication
        .finish(ticket, &binding)
        .unwrap();
    assert_eq!(slot.releasable().unwrap().binding, binding);
    let runtime = slot.release_published().unwrap();
    assert_eq!(runtime.binding, binding);
    assert!(slot.releasable().is_none());
    slot.insert(runtime).unwrap();
    slot.ordinary_mut().unwrap().binding.tcb = 400;
    let expected = slot.releasable().unwrap().binding;
    assert_eq!(expected.tcb, 400);
    assert_eq!(slot.release_published().unwrap().binding, expected);
    drop(partial);
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Suspend(u64),
    Delete(u64),
    Recycle(u64),
    MemoryRecycle(u64),
    Revoke,
    Unmap(u64),
    Release(u64),
    Commit,
}

struct Backend {
    current: ThreadRollbackId,
    events: Vec<Event>,
    fail: Option<usize>,
}

impl Backend {
    fn record(&mut self, event: Event) -> Result<(), u32> {
        if self.fail == Some(self.events.len()) {
            return Err(0xc000009a);
        }
        self.events.push(event);
        Ok(())
    }
}

impl ThreadRollbackIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        id == self.current
    }
    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert!(tcb > 1);
        self.record(Event::Suspend(tcb))
    }
    fn delete_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert!(tcb > 1);
        self.record(Event::Delete(tcb))
    }
    fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        self.record(Event::Revoke)
    }
    fn unmap_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        self.record(Event::Unmap(resource.cap))
    }
    fn release_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        self.record(Event::Release(resource.cap))
    }
    fn commit_rollback(&mut self, _: ThreadRollbackId) {
        self.events.push(Event::Commit);
    }
}

impl ThreadRetirementIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool { id == self.current }
    fn suspend_tcb(&mut self, cap: u64) -> Result<(), u32> { self.record(Event::Suspend(cap)) }
    fn delete_cap(&mut self, _: ConstructionRole, cap: u64) -> Result<(), u32> {
        self.record(Event::Delete(cap))
    }
    fn recycle_slot(&mut self, _: ConstructionRole, slot: u64) -> Result<(), u32> {
        self.record(Event::Recycle(slot))
    }
    fn recycle_failed_memory_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.record(Event::MemoryRecycle(slot))
    }
}

#[test]
fn absent_and_real_tcb_cleanup_retry_every_operation_without_releasing_holds() {
    for tcb in [None, Some(400)] {
        let mut expected = vec![];
        if let Some(cap) = tcb {
            expected.extend([Event::Suspend(cap), Event::Delete(cap), Event::Recycle(cap)]);
        }
        expected.extend([Event::Delete(300), Event::Recycle(300)]);
        let mechanism_events = expected.len();
        expected.extend([
            Event::Revoke,
            Event::Unmap(100),
            Event::Release(100),
            Event::Unmap(200),
            Event::Release(200),
            Event::Commit,
        ]);
        for fail in 0..expected.len() - 1 {
            let (mut slot, ticket, mut partial, drops) = fixture(tcb, true);
            partial.inventory.adopt_object(ConstructionRole::RawCnode, 300).unwrap();
            let inventory = partial.memory.rollback_resources().unwrap();
            let id = slot.retain_failed_construction(ticket, partial).unwrap();
            assert_eq!(
                slot.prepare_cleanup(id, &inventory),
                Err(SlotError::Cleanup(ThreadRollbackError::ConstructionPending))
            );
            let mut backend = Backend {
                current: id,
                events: Vec::with_capacity(expected.len()),
                fail: Some(fail),
            };
            if fail < mechanism_events {
                assert!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).is_err());
            } else {
                without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
                slot.prepare_cleanup(id, &inventory).unwrap();
                assert_eq!(slot.pending().unwrap().cleanup().unwrap().pending_tcb(), None);
                assert!(slot.advance_cleanup(id, &mut backend).is_err());
            }
            assert_eq!(backend.events, expected[..fail]);
            assert_protected(&mut slot, id);
            assert_eq!(drops.get(), 0);
            backend.fail = None;
            without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
            if slot.pending().unwrap().cleanup().is_none() {
                slot.prepare_cleanup(id, &inventory).unwrap();
            }
            slot.advance_cleanup(id, &mut backend).unwrap();
            slot.advance_cleanup(id, &mut backend).unwrap();
            assert_eq!(backend.events, expected);
            assert_eq!(
                slot.pending().unwrap().cleanup().unwrap().stage(),
                ThreadRollbackStage::Complete
            );
            let retired = slot.take_retired_payload(id).unwrap();
            assert!(slot.is_empty());
            assert_eq!(drops.get(), 0);
            drop(retired);
            assert_eq!(drops.get(), 1);
        }
    }
}

#[test]
fn invalid_inventory_and_foreign_attempt_leave_partial_owner_retained() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let (mut other, ticket, partial, _) = fixture(Some(400), true);
    let other_id = other.retain_failed_construction(ticket, partial).unwrap();
    assert_ne!(id, other_id);
    assert_eq!(
        slot.prepare_cleanup(other_id, &[]),
        Err(SlotError::OwnerChanged)
    );
    for _ in 0..3 {
        assert_eq!(
            slot.prepare_cleanup(
                id,
                &[ThreadRollbackResource {
                    cap: 400,
                    kind: Kind::Frame
                }]
            ),
            Err(SlotError::Cleanup(
                ThreadRollbackError::ConstructionPending
            ))
        );
        assert_protected(&mut slot, id);
        assert!(slot.pending().unwrap().cleanup().is_none());
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn all_mechanism_operations_retry_without_replaying_acknowledgements() {
    let expected = vec![
        Event::Suspend(400), Event::Delete(400), Event::Recycle(400),
        Event::Delete(501), Event::Recycle(501),
        Event::Delete(500), Event::Recycle(500),
        Event::Delete(600), Event::Recycle(600),
    ];
    for fail in 0..expected.len() {
        let (mut slot, ticket, mut partial, drops) = fixture(Some(400), true);
        for (role, cap) in [
            (ConstructionRole::RawCnode, 500),
            (ConstructionRole::GuardedCnode, 501),
            (ConstructionRole::SchedContext, 600),
        ] {
            partial.inventory.adopt_object(role, cap).unwrap();
        }
        let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
        let mut backend = Backend { current: id, events: Vec::with_capacity(expected.len()), fail: Some(fail) };
        for _ in 0..3 {
            let error = without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap_err();
            let operation = match expected[fail] {
                Event::Suspend(_) => Operation::Suspend,
                Event::Delete(_) => Operation::Delete,
                _ => Operation::Recycle,
            };
            assert!(matches!(error, SlotError::Retirement(RetirementError::Backend { operation: actual, .. }) if actual == operation));
            assert_eq!(backend.events, expected[..fail]);
            assert_protected(&mut slot, id);
            assert_eq!(slot.prepare_cleanup(id, &[]), Err(SlotError::Cleanup(ThreadRollbackError::ConstructionPending)));
            assert_eq!(drops.get(), 0);
        }
        backend.fail = None;
        without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
        without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
        assert_eq!(backend.events, expected);
        assert!(slot.pending().unwrap().construction_retirement().unwrap().is_complete());
        assert_protected(&mut slot, id);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn empty_and_delete_acknowledged_slots_only_recycle() {
    for role in [ConstructionRole::Tcb, ConstructionRole::RawCnode, ConstructionRole::GuardedCnode, ConstructionRole::SchedContext] {
        for deleted in [false, true] {
            let (mut slot, ticket, mut partial, drops) = fixture(None, true);
            partial.inventory.adopt_empty(role, 500).unwrap();
            if deleted {
                partial.inventory.acknowledge_object(role, 500).unwrap();
                partial.inventory.acknowledge_delete(role, 500).unwrap();
            }
            let id = slot.retain_failed_construction(ticket, partial).unwrap();
            let mut backend = Backend { current: id, events: Vec::with_capacity(1), fail: Some(0) };
            for _ in 0..3 {
                assert_eq!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)),
                    Err(SlotError::Retirement(RetirementError::Backend { role, operation: Operation::Recycle, status: 0xc000009a })));
                assert!(backend.events.is_empty());
                assert_eq!(slot.pending().unwrap().construction_retirement().unwrap().inventory().state(role),
                    if deleted { SlotState::DeleteAcknowledged(500) } else { SlotState::AllocatedEmpty(500) });
            }
            backend.fail = None;
            without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
            assert_eq!(backend.events, [Event::Recycle(500)]);
            assert_protected(&mut slot, id);
            assert_eq!(drops.get(), 0);
        }
    }
}

#[test]
fn retirement_requires_exact_slot_and_backend_attempt() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let (mut other, ticket, partial, _) = fixture(Some(400), false);
    let foreign = other.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: foreign, events: vec![], fail: None };
    assert_eq!(without_allocation(|| slot.advance_construction_retirement(foreign, &mut backend)), Err(SlotError::OwnerChanged));
    assert_eq!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)), Err(SlotError::Retirement(RetirementError::StaleOwner)));
    assert!(backend.events.is_empty());
    assert_eq!(slot.pending().unwrap().construction_retirement().unwrap().inventory().live_tcb(), Some(400));
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn retired_slots_cannot_reenter_memory_cleanup_under_any_resource_kind() {
    let (mut slot, ticket, mut partial, drops) = fixture(Some(400), true);
    partial.inventory.adopt_empty(ConstructionRole::RawCnode, 500).unwrap();
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: id, events: Vec::with_capacity(4), fail: None };
    slot.advance_construction_retirement(id, &mut backend).unwrap();
    for cap in [400, 500] {
        for kind in [Kind::Alias, Kind::Frame, Kind::Mechanism] {
            assert_eq!(without_allocation(|| slot.prepare_cleanup(id, &[ThreadRollbackResource { cap, kind }])),
                Err(SlotError::Cleanup(ThreadRollbackError::ConflictingOwnership)));
        }
    }
    assert_eq!(slot.prepare_cleanup(id, &[ThreadRollbackResource { cap: 700, kind: Kind::Mechanism }]),
        Err(SlotError::Cleanup(ThreadRollbackError::ConflictingOwnership)));
    assert_eq!(backend.events, [Event::Suspend(400), Event::Delete(400), Event::Recycle(400), Event::Recycle(500)]);
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn memory_journal_oom_after_retirement_never_resurrects_tcb_operations() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let resources = partial.memory.rollback_resources().unwrap();
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: id, events: Vec::with_capacity(16), fail: None };
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let result = slot.prepare_cleanup(id, &resources);
    FAIL_ALLOCATIONS.with(|flag| flag.set(false));
    assert_eq!(result, Err(SlotError::Cleanup(ThreadRollbackError::InsufficientResources)));
    assert!(slot.pending().unwrap().cleanup().is_none());
    assert!(slot.pending().unwrap().construction_retirement().unwrap().is_complete());
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
    slot.prepare_cleanup(id, &resources).unwrap();
    assert_eq!(slot.pending().unwrap().cleanup().unwrap().pending_tcb(), None);
    assert_eq!(slot.pending().unwrap().cleanup().unwrap().stage(), ThreadRollbackStage::RevokeMemoryAccess);
    slot.advance_construction_retirement(id, &mut backend).unwrap();
    slot.advance_cleanup(id, &mut backend).unwrap();
    assert_eq!(backend.events, [Event::Suspend(400), Event::Delete(400), Event::Recycle(400),
        Event::Revoke, Event::Unmap(100), Event::Release(100), Event::Unmap(200), Event::Release(200), Event::Commit]);
}

#[test]
fn registered_runtime_cannot_use_construction_retirement() {
    let (mut slot, ticket, partial, _) = fixture(None, false);
    let runtime = slot.publishing_mut(&ticket).unwrap();
    runtime.publication.finish(ticket, &runtime.binding).unwrap();
    runtime.binding.tcb = 400;
    let binding = runtime.binding;
    let id = slot.begin_pending(binding).unwrap();
    let mut backend = Backend { current: id, events: vec![], fail: None };
    assert_eq!(slot.advance_construction_retirement(id, &mut backend), Err(SlotError::Retirement(RetirementError::NotConstruction)));
    assert!(slot.pending().unwrap().construction_retirement().is_none());
    assert!(backend.events.is_empty());
    drop(partial);
}

#[test]
fn pending_memory_is_excluded_before_fallible_journal_preparation() {
    use nt_user_host::thread_memory_access::{check_pending_thread_memory, PendingThreadMemory};
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let owner = slot.pending().unwrap();
    let memory = &owner.runtime().partial.as_ref().unwrap().memory;
    let pending = PendingThreadMemory {
        owner: id,
        memory,
        user_stack_allocation_base: 0,
        user_stack_base: 0,
    };
    assert!(check_pending_thread_memory(2, 0x1000, 1, [pending]).is_err());
    assert!(owner.cleanup().is_none());
}

#[path = "thread_construction/tcb_projection.rs"]
mod tcb_projection;
