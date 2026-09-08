//! Durable, page-isolated storage for unpublished canonical Ps bodies.
//!
//! This arena does not publish PM pointers or grant a provider access. The later publication
//! cutover must transfer these same owners into the retained Ps retirement path. Initial System
//! keeps its dedicated image pages; neither those pages nor win32k pool bodies are adopted here.

use super::*;
use nt_kernel_abi::{ps_reactos_x64 as abi, GuestAddr};
use nt_memory_manager::owned_object_page::{ObjectPageIo, OwnedObjectPage, ROOT_ALIAS_RIGHTS};
use nt_pnp_context::{AddressSlotAllocator, AddressSlotReservation};
use nt_process::{InitialSystemIdentity, ProcessId, ProcessManager, ThreadId, ThreadLifetime};
use ps_object_paging::{PsObjectPaging, PS_OBJECT_ARENA_BASE, PS_OBJECT_ARENA_LIMIT};

const INVALID: u32 = nt_address_space::STATUS_INVALID_PARAMETER;
const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Root {
    system: InitialSystemIdentity,
    cap: u64,
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
    page: OwnedObjectPage<Descriptor, Root>,
}

struct Arena {
    root: Root,
    addresses: AddressSlotAllocator,
    paging: PsObjectPaging<InitialSystemIdentity>,
    rows: Vec<Row>,
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
        rows: Vec::new(),
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
                    || arena.rows.iter().any(|row| row.page.owns_cap(cap))
            })
    }
}

/// This entire branch is owned by Ps, including unallocated addresses. Until exact provider
/// grants are wired, every provider fault here is refused before client/private mapping paths.
pub(super) fn contains_address(address: u64) -> bool {
    (PS_OBJECT_ARENA_BASE..PS_OBJECT_ARENA_LIMIT).contains(&address)
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
                page: OwnedObjectPage::new(descriptor, self.root),
            });
            index
        };
        let mut io = Io {
            paging: &mut self.paging,
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

struct Io<'a> {
    paging: &'a mut PsObjectPaging<InitialSystemIdentity>,
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
    fn validate(&self, target: Root) -> Result<(), u32> {
        if target == self.root {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}
impl ObjectPageIo<Descriptor, Root> for Io<'_> {
    fn acquire_zeroed_frame(&mut self, _: &Descriptor) -> Result<u64, u32> {
        unsafe { frame_acquisition::acquire(self.scratch_base) }
    }
    fn prepare_alias(&mut self, descriptor: &Descriptor, target: Root) -> Result<(), u32> {
        self.validate(target)?;
        if descriptor.address != self.address {
            return Err(INVALID);
        }
        unsafe {
            self.paging
                .ensure_page(target.system, target.cap, self.address)
        }
        .map_err(|_| RESOURCES)
    }
    fn copy(&mut self, frame: u64, target: Root) -> (u64, u32) {
        if let Err(error) = self.validate(target) {
            return (0, error);
        }
        let Some(slot) = try_alloc_slot() else {
            return (0, RESOURCES);
        };
        let error = unsafe { copy_cap_into_r(frame, slot) };
        // Even failed copies return their allocated-empty slot to the retained alias owner.
        (slot, u32::try_from(error).unwrap_or(INVALID))
    }
    fn map(&mut self, slot: u64, target: Root, rights: u64) -> Result<(), u32> {
        self.validate(target)?;
        if rights != ROOT_ALIAS_RIGHTS {
            return Err(INVALID);
        }
        status(unsafe { page_map_r(slot, self.address, RW_NX, target.cap) })
    }
    fn unmap(&mut self, slot: u64, target: Root) -> Result<(), u32> {
        self.validate(target)?;
        status(unsafe { page_unmap_r(slot) })
    }
    fn delete(&mut self, slot: u64, target: Root) -> Result<(), u32> {
        self.validate(target)?;
        status(unsafe { cnode_delete_r(slot) })
    }
    fn recycle_alias(&mut self, slot: u64, target: Root) -> Result<(), u32> {
        self.validate(target)?;
        unsafe { root_slot_recycle::publish_unretyped(slot) }.map_err(|_| INVALID)
    }
    fn initialize(&mut self, descriptor: &Descriptor, target: Root) -> Result<(), u32> {
        self.validate(target)?;
        if descriptor.address != self.address {
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
