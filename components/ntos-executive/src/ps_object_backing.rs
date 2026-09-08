//! Durable, page-isolated canonical Ps bodies and their exact provider mappings.
//!
//! Initial System keeps its dedicated image pages; neither those pages nor win32k pool bodies
//! are adopted here. PM withdrawal owns retirement of published ordinary bodies.

use super::*;
use nt_kernel_abi::{ps_reactos_x64 as abi, GuestAddr};
use nt_memory_manager::owned_object_page::{ObjectPageIo, OwnedObjectPage, ROOT_ALIAS_RIGHTS};
use nt_pnp_context::{AddressSlotAllocator, AddressSlotReservation};
use nt_process::process_object_retirement::ProcessObjectRetirement;
use nt_process::{InitialSystemIdentity, ProcessId, ProcessManager, ThreadId, ThreadLifetime};
use ps_object_paging::{PsObjectPaging, PS_OBJECT_ARENA_BASE, PS_OBJECT_ARENA_LIMIT};
use ps_object_provider::{ProviderRoot, ProviderRoots};

const INVALID: u32 = nt_address_space::STATUS_INVALID_PARAMETER;
const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Root {
    system: InitialSystemIdentity,
    cap: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MappingTarget {
    Executive(Root),
    Provider(ProviderRoot),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyId {
    Process(ProcessId),
    Thread(ThreadId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Initialization {
    Process(abi::ProcessInitialization),
    Thread {
        lifetime: ThreadLifetime,
        fields: abi::ThreadInitialization,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Descriptor {
    id: BodyId,
    address: u64,
    initialization: Initialization,
}

struct Row {
    // Kept even after backing retirement if address release has not been acknowledged.
    reservation: Option<AddressSlotReservation>,
    page: OwnedObjectPage<Descriptor, MappingTarget>,
    phase: BodyPhase,
    current_thread_lifetime: Option<ThreadLifetime>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyPhase {
    Prepared,
    Published,
    Retiring { published: bool },
}

impl Row {
    fn was_published(&self) -> bool {
        matches!(
            self.phase,
            BodyPhase::Published | BodyPhase::Retiring { published: true }
        )
    }

    fn pid(&self) -> ProcessId {
        match self.page.descriptor().initialization {
            Initialization::Process(fields) => fields.process_id as ProcessId,
            Initialization::Thread { lifetime, .. } => lifetime.process_id(),
        }
    }
}

struct Arena {
    root: Root,
    addresses: AddressSlotAllocator,
    paging: PsObjectPaging<InitialSystemIdentity>,
    providers: ProviderRoots,
    rows: Vec<Row>,
    last_census: [usize; 9],
}

static mut ARENA: Option<Arena> = None;
static BORROWED: AtomicBool = AtomicBool::new(false);

struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

/// Called once from root bootstrap after designation, before any provider can execute. Branch
/// 129 is exclusively reserved here; metadata publication does not allocate any paging objects.
pub(super) unsafe fn initialize(system: InitialSystemIdentity) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let slot = &mut *core::ptr::addr_of_mut!(ARENA);
    if slot.is_some() {
        return Err(INVALID);
    }
    *slot = Some(Arena {
        root: Root {
            system,
            cap: CAP_INIT_THREAD_VSPACE,
        },
        addresses: AddressSlotAllocator::new(PS_OBJECT_ARENA_BASE, PS_OBJECT_ARENA_LIMIT, 0x1000),
        paging: PsObjectPaging::new(system, CAP_INIT_THREAD_VSPACE).map_err(|_| INVALID)?,
        providers: ProviderRoots::new(),
        rows: Vec::new(),
        last_census: [0; 9],
    });
    Ok(())
}

/// Deny-only cross-owner checks include empty slots and failed mapping candidates. Never inspect
/// an arena already mutably borrowed by an allocation/cleanup operation.
pub(super) fn owns_root_cap(cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe {
        (&*core::ptr::addr_of!(ARENA))
            .as_ref()
            .is_some_and(|arena| {
                arena.root.cap == cap
                    || arena.paging.owns_cap(cap)
                    || arena.providers.owns_cap(cap)
                    || arena.rows.iter().any(|row| row.page.owns_cap(cap))
            })
    }
}

/// This entire branch is owned by Ps, including unallocated addresses. Until exact provider
/// grants are wired, every provider fault here is refused before client/private mapping paths.
pub(super) fn contains_address(address: u64) -> bool {
    (PS_OBJECT_ARENA_BASE..PS_OBJECT_ARENA_LIMIT).contains(&address)
}

/// Report retained ownership, not inferred boot success. A cleanup candidate remains counted
/// until its exact owner has acknowledged release; unchanged checkpoints produce no output.
pub(super) fn print_census_changes() {
    let Ok(_borrow) = Borrow::acquire() else {
        return;
    };
    let Some(arena) = (unsafe { &mut *core::ptr::addr_of_mut!(ARENA) }).as_mut() else {
        return;
    };
    let mut counts = [0; 9];
    for row in &arena.rows {
        counts[match row.phase {
            BodyPhase::Prepared => 0,
            BodyPhase::Published => 1,
            BodyPhase::Retiring { .. } => 2,
        }] += 1;
        let page = row.page.stats();
        counts[3] += page.backing_frames;
        counts[4] += page.live_aliases;
        counts[5] += page.pending_aliases;
    }
    counts[6..].copy_from_slice(&arena.providers.census());
    if counts == arena.last_census {
        return;
    }
    arena.last_census = counts;
    print_str(b"[ps-backing]");
    for (label, count) in [
        (b" prepared=".as_slice(), counts[0]),
        (b" published=".as_slice(), counts[1]),
        (b" retiring=".as_slice(), counts[2]),
        (b" frames=".as_slice(), counts[3]),
        (b" live-aliases=".as_slice(), counts[4]),
        (b" pending-aliases=".as_slice(), counts[5]),
        (b" providers=".as_slice(), counts[6]),
        (b" retiring-providers=".as_slice(), counts[7]),
        (b" released-providers=".as_slice(), counts[8]),
    ] {
        print_str(label);
        print_u64(count as u64);
    }
    print_str(b"\n");
}

/// # Safety
/// `target` must identify the root-assigned provider VSpace, before any execution can touch the
/// reserved branch. The retained copy remains in this arena through all failed constructions.
pub(super) unsafe fn register_provider(target: ProviderRoot) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.providers.register(target)
}

/// Deny teardown/reuse of the original VSpace until retained aliases, tables and root have drained.
pub(super) fn references_provider_vspace(pml4: u64) -> bool {
    if pml4 == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    unsafe {
        (&*core::ptr::addr_of!(ARENA))
            .as_ref()
            .is_some_and(|arena| arena.providers.references_vspace(pml4))
    }
}

/// # Safety
/// Root has admitted this provider to operate on the exact current PM thread/process objects.
/// This must finish before provider execution, and may not pump component IPC while borrowed.
pub(super) unsafe fn grant_published_pair(
    pm: &ProcessManager,
    lifetime: ThreadLifetime,
    target: ProviderRoot,
    scratch_base: u64,
) -> Result<(), u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    arena.providers.mapping_root(target)?;
    let process = arena
        .existing(BodyId::Process(lifetime.process_id()))
        .ok_or(INVALID)?;
    let thread = arena
        .existing(BodyId::Thread(lifetime.thread_id()))
        .ok_or(INVALID)?;
    if pm.thread_lifetime(lifetime.thread_id()) != Some(lifetime)
        || pm.process_kernel_object(lifetime.process_id())
            != Some(arena.rows[process].page.descriptor().address)
        || pm.thread_kernel_object(lifetime.thread_id())
            != Some(arena.rows[thread].page.descriptor().address)
        || arena.rows[thread].current_thread_lifetime != Some(lifetime)
        || [process, thread]
            .into_iter()
            .any(|index| arena.rows[index].phase != BodyPhase::Published)
    {
        return Err(INVALID);
    }
    let _durable = allocator::enter_durable();
    for index in [process, thread] {
        let row = &mut arena.rows[index];
        let mut io = Io {
            paging: &mut arena.paging,
            providers: &mut arena.providers,
            root: arena.root,
            scratch_base,
            address: row.page.descriptor().address,
            borrow: &borrow,
        };
        row.page
            .map_alias(MappingTarget::Provider(target), ROOT_ALIAS_RIGHTS, &mut io)?;
    }
    Ok(())
}

/// # Safety
/// Root has stopped provider execution and closed all dispatch/callback admission for this exact
/// target. Closing leaf admission is sticky; failures retain every remaining leaf/table/root.
pub(super) unsafe fn retire_provider(target: ProviderRoot, scratch_base: u64) -> Result<(), u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.providers.close_admission(target)?;
    for row in &mut arena.rows {
        let mut io = Io {
            paging: &mut arena.paging,
            providers: &mut arena.providers,
            root: arena.root,
            scratch_base,
            address: row.page.descriptor().address,
            borrow: &borrow,
        };
        row.page
            .retire_alias(MappingTarget::Provider(target), &mut io)?;
    }
    arena.providers.retire_descendants_drained(target)
}

/// A private-constructor proof used only by the page owner's final backing transfer, after all
/// aliases have drained. It cannot outlive the arena borrow or authorize another frame.
pub(crate) struct FrameRelease<'a> {
    frame: u64,
    _borrow: &'a Borrow,
}
impl FrameRelease<'_> {
    pub(crate) fn frame(&self) -> u64 {
        self.frame
    }
}

impl Arena {
    fn validate(&self, pm: &ProcessManager) -> Result<(), u32> {
        if pm.initial_system_identity() == Some(self.root.system) {
            Ok(())
        } else {
            Err(INVALID)
        }
    }

    fn existing(&self, id: BodyId) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.page.descriptor().id == id)
    }

    fn prepare(
        &mut self,
        id: BodyId,
        initialization: impl FnOnce(u64) -> Initialization,
        scratch_base: u64,
        borrow: &Borrow,
    ) -> Result<u64, u32> {
        let _durable = allocator::enter_durable();
        let index = if let Some(index) = self.existing(id) {
            if self.rows[index].phase != BodyPhase::Prepared {
                return Err(INVALID);
            }
            let descriptor = self.rows[index].page.descriptor();
            if descriptor.initialization != initialization(descriptor.address) {
                return Err(INVALID);
            }
            index
        } else {
            // Capacity precedes address acquisition; ownership is published before any syscall.
            self.rows.try_reserve(1).map_err(|_| RESOURCES)?;
            let reservation = self.addresses.allocate(0x1000).map_err(|_| RESOURCES)?;
            let address = reservation.address();
            let descriptor = Descriptor {
                id,
                address,
                initialization: initialization(address),
            };
            let index = self.rows.len();
            self.rows.push(Row {
                reservation: Some(reservation),
                page: OwnedObjectPage::new(descriptor, MappingTarget::Executive(self.root)),
                phase: BodyPhase::Prepared,
                current_thread_lifetime: match descriptor.initialization {
                    Initialization::Thread { lifetime, .. } => Some(lifetime),
                    Initialization::Process(_) => None,
                },
            });
            index
        };
        let mut io = Io {
            paging: &mut self.paging,
            providers: &mut self.providers,
            root: self.root,
            scratch_base,
            address: self.rows[index].page.descriptor().address,
            borrow,
        };
        self.rows[index].page.construct(&mut io)?;
        Ok(self.rows[index].page.descriptor().address)
    }
}

/// Prepare fresh unpublished storage only. This deliberately does not change PM lookup or
/// win32k dispatch; callers may publish only in the later, complete provider/retirement cutover.
pub(super) unsafe fn prepare_process(
    pm: &ProcessManager,
    pid: ProcessId,
    scratch_base: u64,
) -> Result<u64, u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    if pid == arena.root.system.process_id() || pm.process_kernel_object(pid).is_some() {
        return Err(INVALID);
    }
    let peb = pm.query_process_basic(pid, u64::MAX)?.peb_base_address;
    arena.prepare(
        BodyId::Process(pid),
        |address| {
            Initialization::Process(abi::ProcessInitialization {
                body: GuestAddr(address),
                process_id: u64::from(pid),
                peb: GuestAddr(peb),
            })
        },
        scratch_base,
        &borrow,
    )
}

pub(super) unsafe fn prepare_thread(
    pm: &ProcessManager,
    lifetime: ThreadLifetime,
    scratch_base: u64,
) -> Result<u64, u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    if pm.thread_lifetime(lifetime.thread_id()) != Some(lifetime)
        || lifetime.thread_id() == arena.root.system.thread_id()
        || pm.thread_kernel_object(lifetime.thread_id()).is_some()
    {
        return Err(INVALID);
    }
    let process_index = arena
        .existing(BodyId::Process(lifetime.process_id()))
        .ok_or(INVALID)?;
    let process = &arena.rows[process_index].page;
    if !process.is_initialized() || process.is_released() {
        return Err(INVALID);
    }
    let process_body = process.descriptor().address;
    let thread = pm.thread(lifetime.thread_id()).ok_or(INVALID)?;
    let (teb, system_thread) = (thread.teb_base, thread.is_system_thread);
    arena.prepare(
        BodyId::Thread(lifetime.thread_id()),
        |address| Initialization::Thread {
            lifetime,
            fields: abi::ThreadInitialization {
                body: GuestAddr(address),
                process_body: GuestAddr(process_body),
                process_id: u64::from(lifetime.process_id()),
                thread_id: u64::from(lifetime.thread_id()),
                teb: GuestAddr(teb),
                system_thread,
            },
        },
        scratch_base,
        &borrow,
    )
}

/// Abort only unpublished storage. Published-body cleanup must be owned by the PM withdrawal
/// ticket, and is intentionally unavailable here. Threads drain before their referenced process.
pub(super) unsafe fn abort_unpublished(
    pm: &ProcessManager,
    body: u64,
    scratch_base: u64,
) -> Result<(), u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let index = arena
        .rows
        .iter()
        .position(|row| row.page.descriptor().address == body)
        .ok_or(INVALID)?;
    let id = arena.rows[index].page.descriptor().id;
    if arena.rows[index].phase != BodyPhase::Prepared {
        return Err(INVALID);
    }
    match id {
        BodyId::Process(pid) => {
            if pm.process(pid).is_none()
                || pm.process_kernel_object(pid).is_some()
                || arena.rows.iter().any(|row| {
                    matches!(row.page.descriptor().initialization,
                    Initialization::Thread { fields, .. } if fields.process_body.0 == body)
                })
            {
                return Err(INVALID);
            }
        }
        BodyId::Thread(tid) => {
            if pm.thread(tid).is_none() || pm.thread_kernel_object(tid).is_some() {
                return Err(INVALID);
            }
        }
    }
    let mut io = Io {
        paging: &mut arena.paging,
        providers: &mut arena.providers,
        root: arena.root,
        scratch_base,
        address: body,
        borrow: &borrow,
    };
    arena.rows[index].page.retire(&mut io)?;
    let reservation = arena.rows[index].reservation.take().ok_or(INVALID)?;
    if let Err(error) = arena.addresses.release(reservation) {
        arena.rows[index].reservation = Some(error.into_reservation());
        return Err(INVALID);
    }
    arena.rows.swap_remove(index);
    Ok(())
}

/// Publish only already initialized storage. PM preflights both pointers and the exact thread
/// activation before either becomes visible. No syscall/allocation/reentry separates its commit
/// from these sticky ownership phases; withdrawal can never make the rows abortable again.
pub(super) unsafe fn publish_prepared_pair(
    pm: &mut ProcessManager,
    lifetime: ThreadLifetime,
) -> Result<(u64, u64), u32> {
    let _borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let process = arena
        .existing(BodyId::Process(lifetime.process_id()))
        .ok_or(INVALID)?;
    let thread = arena
        .existing(BodyId::Thread(lifetime.thread_id()))
        .ok_or(INVALID)?;
    if [process, thread].into_iter().any(|index| {
        matches!(arena.rows[index].phase, BodyPhase::Retiring { .. })
            || !arena.rows[index].page.is_initialized()
    }) || arena.rows[thread].current_thread_lifetime != Some(lifetime)
    {
        return Err(INVALID);
    }
    let eprocess = arena.rows[process].page.descriptor().address;
    let ethread = arena.rows[thread].page.descriptor().address;
    if !pm.publish_kernel_object_pair(lifetime, eprocess, ethread) {
        return Err(INVALID);
    }
    arena.rows[process].phase = BodyPhase::Published;
    arena.rows[thread].phase = BodyPhase::Published;
    Ok((eprocess, ethread))
}

/// Commit PM activation and refresh its stable body without an intervening provider entry.
///
/// # Safety
/// The target TCB remains suspended. Every old-activation execution/request reference is drained;
/// the alias owner separately proves that even failed non-root mapping candidates are gone.
pub(super) unsafe fn commit_thread_activation(
    pm: &mut ProcessManager,
    plan: nt_process::ThreadActivationPlan,
    handle: nt_process::HandleReservation,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let Some(index) = arena.existing(BodyId::Thread(plan.thread_id())) else {
        if pm
            .thread_kernel_object(plan.thread_id())
            .is_some_and(contains_address)
        {
            return Err(INVALID);
        }
        return pm.commit_thread_activation_with_handle(plan, handle);
    };
    let row = &mut arena.rows[index];
    let body = row.page.descriptor().address;
    if row.phase != BodyPhase::Published
        || row.current_thread_lifetime != Some(plan.expected_lifetime())
        || pm.thread_kernel_object(plan.thread_id()) != Some(body)
        || row
            .page
            .live_alias(MappingTarget::Executive(arena.root))
            .is_none()
        || !row.page.non_root_aliases_drained()
    {
        return Err(INVALID);
    }
    let Initialization::Thread { mut fields, .. } = row.page.descriptor().initialization else {
        return Err(INVALID);
    };
    if pm.process_kernel_object(plan.process_id()) != Some(fields.process_body.0) {
        return Err(INVALID);
    }
    fields.teb = GuestAddr(plan.teb_base());
    fields.system_thread = pm.thread(plan.thread_id()).ok_or(INVALID)?.is_system_thread;
    let bytes = core::slice::from_raw_parts_mut(body as *mut u8, abi::ETHREAD_BODY_BYTES);
    abi::validate_thread_activation(bytes, fields).map_err(|_| INVALID)?;
    pm.commit_thread_activation_with_handle(plan, handle)?;
    // Both owners remain exclusively borrowed. No allocation, syscall or provider byte write can
    // invalidate the preflight between PM generation publication and these bounded field writes.
    abi::refresh_thread_activation(bytes, fields).expect("exclusive prevalidated ETHREAD refresh");
    row.current_thread_lifetime = pm.thread_lifetime(plan.thread_id());
    Ok(())
}

/// Physical cleanup has completed, but the arena still owns the virtual-address reservations.
/// Dropping this receipt does not release them. The PM withdrawal owner retains this receipt
/// across failed PM finalization and releases addresses only after the exact PM commit succeeds.
#[must_use]
pub(crate) struct ProcessBackingRetirement {
    system: InitialSystemIdentity,
    pid: ProcessId,
}

/// Validate the entire withdrawn object set before retiring any storage. A body outside the
/// arena belongs to its existing provider owner; an arena address without its exact row is always
/// an error. This also drains prepared, never-published rows attached to the withdrawn process.
pub(super) unsafe fn retire_withdrawn(
    pm: &ProcessManager,
    ticket: &ProcessObjectRetirement,
    scratch_base: u64,
) -> Result<ProcessBackingRetirement, u32> {
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let snapshot = pm.process_object_retirement_snapshot(ticket)?;
    let validate_body = |id, body: Option<u64>| -> Result<(), u32> {
        if let Some(body) = body.filter(|body| contains_address(*body)) {
            let index = arena.existing(id).ok_or(INVALID)?;
            if arena.rows[index].page.descriptor().address != body
                || !arena.rows[index].was_published()
            {
                return Err(INVALID);
            }
        }
        Ok(())
    };
    validate_body(BodyId::Process(snapshot.pid), snapshot.process_body)?;
    for index in 0..snapshot.thread_count {
        let thread = pm.process_object_retirement_thread(ticket, index)?;
        validate_body(BodyId::Thread(thread.lifetime.thread_id()), thread.body)?;
    }
    for row in arena.rows.iter().filter(|row| row.pid() == snapshot.pid) {
        let body = match row.page.descriptor().id {
            BodyId::Process(pid) if pid == snapshot.pid => snapshot.process_body,
            BodyId::Thread(tid) => {
                let mut found = None;
                for index in 0..snapshot.thread_count {
                    let thread = pm.process_object_retirement_thread(ticket, index)?;
                    if thread.lifetime.thread_id() == tid {
                        if row.was_published()
                            && row.current_thread_lifetime != Some(thread.lifetime)
                        {
                            return Err(INVALID);
                        }
                        found = Some(thread.body);
                        break;
                    }
                }
                found.ok_or(INVALID)?
            }
            _ => return Err(INVALID),
        };
        if !row.was_published() {
            if body.is_some() {
                return Err(INVALID);
            }
        } else if body != Some(row.page.descriptor().address) {
            return Err(INVALID);
        }
    }
    for row in arena
        .rows
        .iter_mut()
        .filter(|row| row.pid() == snapshot.pid)
    {
        row.phase = BodyPhase::Retiring {
            published: row.was_published(),
        };
    }
    for threads in [true, false] {
        for row in arena
            .rows
            .iter_mut()
            .filter(|row| row.pid() == snapshot.pid)
        {
            if matches!(row.page.descriptor().id, BodyId::Thread(_)) != threads {
                continue;
            }
            let mut io = Io {
                paging: &mut arena.paging,
                providers: &mut arena.providers,
                root: arena.root,
                scratch_base,
                address: row.page.descriptor().address,
                borrow: &borrow,
            };
            row.page.retire(&mut io)?;
        }
    }
    Ok(ProcessBackingRetirement {
        system: arena.root.system,
        pid: snapshot.pid,
    })
}

/// # Safety
/// The caller must have received success from PM finish for the exact withdrawal ticket that
/// produced `receipt`. Failed address release retains the receipt and remaining reservations.
pub(super) unsafe fn release_retired_addresses(
    receipt: ProcessBackingRetirement,
) -> Result<(), (u32, ProcessBackingRetirement)> {
    let result = (|| {
        let _borrow = Borrow::acquire()?;
        let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
            .as_mut()
            .ok_or(INVALID)?;
        if arena.root.system != receipt.system {
            return Err(INVALID);
        }
        if arena
            .rows
            .iter()
            .filter(|row| row.pid() == receipt.pid)
            .any(|row| !matches!(row.phase, BodyPhase::Retiring { .. }) || !row.page.is_released())
        {
            return Err(INVALID);
        }
        while let Some(index) = arena.rows.iter().position(|row| row.pid() == receipt.pid) {
            let reservation = arena.rows[index].reservation.take().ok_or(INVALID)?;
            if let Err(error) = arena.addresses.release(reservation) {
                arena.rows[index].reservation = Some(error.into_reservation());
                return Err(INVALID);
            }
            arena.rows.swap_remove(index);
        }
        Ok(())
    })();
    result.map_err(|status| (status, receipt))
}

struct Io<'a> {
    paging: &'a mut PsObjectPaging<InitialSystemIdentity>,
    providers: &'a mut ProviderRoots,
    root: Root,
    scratch_base: u64,
    address: u64,
    borrow: &'a Borrow,
}
fn status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(u32::try_from(error).unwrap_or(INVALID))
    }
}
impl Io<'_> {
    fn validate_retained(&self, target: MappingTarget) -> Result<(), u32> {
        match target {
            MappingTarget::Executive(root) if root == self.root => Ok(()),
            MappingTarget::Provider(provider) if self.providers.retains(provider) => Ok(()),
            _ => Err(INVALID),
        }
    }

    fn mapping_root(&self, target: MappingTarget) -> Result<u64, u32> {
        match target {
            MappingTarget::Executive(root) if root == self.root => Ok(root.cap),
            MappingTarget::Provider(provider) => self.providers.mapping_root(provider),
            _ => Err(INVALID),
        }
    }
}
impl ObjectPageIo<Descriptor, MappingTarget> for Io<'_> {
    fn acquire_zeroed_frame(&mut self, _: &Descriptor) -> Result<u64, u32> {
        unsafe { frame_acquisition::acquire(self.scratch_base) }
    }
    fn prepare_alias(&mut self, descriptor: &Descriptor, target: MappingTarget) -> Result<(), u32> {
        self.mapping_root(target)?;
        if descriptor.address != self.address {
            return Err(INVALID);
        }
        match target {
            MappingTarget::Executive(root) => {
                unsafe { self.paging.ensure_page(root.system, root.cap, self.address) }
                    .map_err(|_| RESOURCES)
            }
            MappingTarget::Provider(provider) => unsafe {
                self.providers.ensure_page(provider, self.address)
            },
        }
    }
    fn copy(&mut self, frame: u64, target: MappingTarget) -> (u64, u32) {
        if let Err(error) = self.mapping_root(target) {
            return (0, error);
        }
        let Some(slot) = try_alloc_slot() else {
            return (0, RESOURCES);
        };
        let error = unsafe { copy_cap_into_r(frame, slot) };
        // Even failed copies return their allocated-empty slot to the retained alias owner.
        (slot, u32::try_from(error).unwrap_or(INVALID))
    }
    fn map(&mut self, slot: u64, target: MappingTarget, rights: u64) -> Result<(), u32> {
        let root = self.mapping_root(target)?;
        if rights != ROOT_ALIAS_RIGHTS {
            return Err(INVALID);
        }
        status(unsafe { page_map_r(slot, self.address, RW_NX, root) })
    }
    fn unmap(&mut self, slot: u64, target: MappingTarget) -> Result<(), u32> {
        self.validate_retained(target)?;
        status(unsafe { page_unmap_r(slot) })
    }
    fn delete(&mut self, slot: u64, target: MappingTarget) -> Result<(), u32> {
        self.validate_retained(target)?;
        status(unsafe { cnode_delete_r(slot) })
    }
    fn recycle_alias(&mut self, slot: u64, target: MappingTarget) -> Result<(), u32> {
        self.validate_retained(target)?;
        unsafe { root_slot_recycle::publish_unretyped(slot) }.map_err(|_| INVALID)
    }
    fn initialize(&mut self, descriptor: &Descriptor, target: MappingTarget) -> Result<(), u32> {
        if target != MappingTarget::Executive(self.root) || descriptor.address != self.address {
            return Err(INVALID);
        }
        let bytes = unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, 0x1000) };
        match descriptor.initialization {
            Initialization::Process(fields) => abi::initialize_process(bytes, fields),
            Initialization::Thread { fields, .. } => abi::initialize_thread(bytes, fields),
        }
        .map_err(|_| INVALID)
    }
    fn release_backing(&mut self, frame: u64) -> Result<(), u32> {
        let permit = FrameRelease {
            frame,
            _borrow: self.borrow,
        };
        unsafe {
            frame_recycle::prepare_ps_owned(&permit)?;
            frame_recycle::publish_ps_owned(&permit)
        }
    }
}
