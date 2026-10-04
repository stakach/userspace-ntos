//! Exact process-owned dynamic parents, separate from the spawn-owned paging skeleton.

use super::*;
use nt_memory_manager::owned_paging_structure::{
    OwnedPagingStructure, PagingStructureError, PagingStructureIo,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Level {
    Pdpt,
    Directory,
}
impl Level {
    fn span(self) -> u64 {
        match self {
            Self::Pdpt => 1 << 39,
            Self::Directory => 1 << 30,
        }
    }
    fn object(self) -> u64 {
        match self {
            Self::Pdpt => OBJ_X86_PDPT,
            Self::Directory => OBJ_X86_PAGE_DIRECTORY,
        }
    }
    fn map_label(self) -> u64 {
        match self {
            Self::Pdpt => LBL_X86_PDPT_MAP,
            Self::Directory => LBL_X86_PAGE_DIRECTORY_MAP,
        }
    }
    fn unmap_label(self) -> u64 {
        match self {
            Self::Pdpt => sel4_rt::LBL_X86_PDPT_UNMAP,
            Self::Directory => sel4_rt::LBL_X86_PAGE_DIRECTORY_UNMAP,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Descriptor {
    pi: usize,
    process: nt_memory_manager::ProcessIdentity,
    pml4: u64,
    level: Level,
    base: u64,
}
struct Row {
    owner: OwnedPagingStructure<Descriptor>,
    retyped: bool,
    charged: bool,
    retiring: bool,
}
struct Ledger {
    rows: Vec<Row>,
    growths: u64,
    allocation_failures: u64,
}
static mut LEDGER: Ledger = Ledger {
    rows: Vec::new(),
    growths: 0,
    allocation_failures: 0,
};
static BORROWED: AtomicBool = AtomicBool::new(false);
struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

fn status(error: PagingStructureError) -> u32 {
    match error {
        PagingStructureError::Backend(status) => status,
        _ => nt_process::STATUS_INVALID_HANDLE,
    }
}
fn checked(label: u64) -> Result<(), u32> {
    if label == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

fn current(handler: &ExecNtHandler, descriptor: Descriptor) -> bool {
    handler.capture_process_identity(descriptor.pi) == Some(descriptor.process)
        && handler.hosted_process_vspace(descriptor.pi) == Some(descriptor.pml4)
        && handler
            .loop_ctx
            .and_then(|ctx| unsafe { ctx.for_process(descriptor.pi) })
            .is_some_and(|ctx| unsafe {
                (&*ctx.procs)
                    .get(descriptor.pi)
                    .is_some_and(|target| target.pml4 == descriptor.pml4)
            })
}

fn initial_parent_at(caps: HostedProcessVspaceCaps, level: Level, base: u64) -> bool {
    let span = level.span();
    let (image, kuser) = match level {
        Level::Pdpt => (caps.image_pdpt, caps.kuser_pdpt),
        Level::Directory => (caps.image_pd, caps.kuser_pd),
    };
    image != 0 && base == (IMAGE_BASE & !(span - 1))
        || kuser != 0 && base == (KUSER_VA & !(span - 1))
}
fn initial_parent(caps: HostedProcessVspaceCaps, descriptor: Descriptor) -> bool {
    initial_parent_at(caps, descriptor.level, descriptor.base)
}

fn spawn_process_is_current(descriptor: Descriptor, caps: HostedProcessVspaceCaps) -> bool {
    descriptor.process.generation == nt_memory_manager::ProcessGeneration::Hosted(caps.generation)
        && descriptor.pml4 == caps.pml4
        && process_root_is_owned(descriptor)
}

fn process_root_is_owned(descriptor: Descriptor) -> bool {
    descriptor.pml4 != 0
        && unsafe { frame_recycle::validate_owned_backing(descriptor.pml4) }.is_ok()
        && unsafe { (&*core::ptr::addr_of!(PROCESS_MECHANISM_WORK)).get(descriptor.pi) }
            .is_some_and(|owner| {
                owner.pid == descriptor.process.pid
                    && descriptor.process.generation
                        == nt_memory_manager::ProcessGeneration::Hosted(owner.generation)
            })
        && hosted_process_runtime_for_pi(descriptor.pi).is_some_and(|runtime| {
            descriptor.process.generation
                == nt_memory_manager::ProcessGeneration::Hosted(runtime.generation)
        })
}

enum Admission<'a> {
    Live(&'a mut ExecNtHandler),
    Spawn(HostedProcessVspaceCaps),
}

struct Io<'a> {
    admission: Admission<'a>,
    descriptor: Descriptor,
    retyped: &'a mut bool,
    charged: &'a mut bool,
}
impl Io<'_> {
    fn validate(&self, descriptor: &Descriptor) -> Result<(), u32> {
        let valid = match &self.admission {
            Admission::Live(handler) => current(handler, *descriptor),
            Admission::Spawn(caps) => spawn_process_is_current(*descriptor, *caps),
        };
        if *descriptor == self.descriptor && valid {
            Ok(())
        } else {
            Err(nt_process::STATUS_INVALID_HANDLE)
        }
    }
}
impl PagingStructureIo<Descriptor> for Io<'_> {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        try_alloc_slot().ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn retype(&mut self, slot: u64, descriptor: &Descriptor) -> Result<(), u32> {
        self.validate(descriptor)?;
        let charge = match &mut self.admission {
            Admission::Live(handler) => Some(unsafe {
                handler.prepare_process_commit_charge(
                    descriptor.process.pid,
                    descriptor.pi,
                    4096,
                )?
            }),
            Admission::Spawn(_) => None,
        };
        checked(unsafe {
            untyped_retype_r(
                CAP_INIT_UNTYPED,
                descriptor.level.object(),
                PAGING_BITS,
                1,
                slot,
            )
        })?;
        *self.retyped = true;
        if let (Admission::Live(handler), Some(charge)) = (&mut self.admission, charge) {
            handler.commit_process_commit_charge(charge);
            *self.charged = true;
        }
        Ok(())
    }
    fn map(&mut self, slot: u64, descriptor: &Descriptor) -> Result<(), u32> {
        self.validate(descriptor)?;
        checked(unsafe {
            paging_struct_map_r(
                slot,
                descriptor.level.map_label(),
                descriptor.base,
                descriptor.pml4,
            )
        })
    }
    fn unmap(&mut self, slot: u64, descriptor: &Descriptor) -> Result<(), u32> {
        self.validate(descriptor)?;
        checked(unsafe { paging_struct_map_r(slot, descriptor.level.unmap_label(), 0, 0) })
    }
    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        checked(unsafe { cnode_delete_r(slot) })
    }
    fn recycle_retyped(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_empty(slot) }
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
        *self.retyped = false;
        if *self.charged {
            let Admission::Live(handler) = &mut self.admission else {
                unreachable!("only live accounting can acknowledge a paging charge");
            };
            handler.release_process_page_table_commitment(self.descriptor.pi, 1);
            *self.charged = false;
        }
        Ok(())
    }
    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)
    }
}

fn reserve_path(
    ledger: &mut Ledger,
    caps: HostedProcessVspaceCaps,
    path: [Descriptor; 2],
) -> Result<(), u32> {
    let target = path[0];
    if ledger.rows.iter().any(|row| {
        let old = row.owner.descriptor();
        old.pi == target.pi
            && (old.process != target.process || old.pml4 != target.pml4 || row.retiring)
    }) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let missing = path
        .iter()
        .filter(|descriptor| {
            !initial_parent(caps, **descriptor)
                && !ledger
                    .rows
                    .iter()
                    .any(|row| row.owner.descriptor() == *descriptor)
        })
        .count();
    let old_capacity = ledger.rows.capacity();
    {
        let _durable = allocator::enter_durable();
        if ledger.rows.try_reserve(missing).is_err() {
            ledger.allocation_failures = ledger.allocation_failures.saturating_add(1);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    if ledger.rows.capacity() != old_capacity {
        ledger.growths = ledger.growths.saturating_add(1);
    }
    for descriptor in path {
        if !initial_parent(caps, descriptor)
            && !ledger
                .rows
                .iter()
                .any(|row| *row.owner.descriptor() == descriptor)
        {
            ledger.rows.push(Row {
                owner: OwnedPagingStructure::new(descriptor),
                retyped: false,
                charged: false,
                retiring: false,
            });
        }
    }
    Ok(())
}

/// Constructor-owned initial caps may be borrowed before runtime publication. New parents require
/// an already registered exact Process mechanism and are retained in the same live paging ledger.
pub(crate) unsafe fn ensure_spawn_user_paging_parents(
    pi: usize,
    generation: u64,
    lifetime: nt_memory_manager::MemoryLifetime,
    caps: HostedProcessVspaceCaps,
    page: u64,
) -> Result<(), u32> {
    if pi >= MAX_PI
        || generation == 0
        || caps.generation != generation
        || caps.pml4 == 0
        || !lifetime.is_valid()
        || page & 4095 != 0
        || page >= USER_ADDRESS_LIMIT
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    frame_recycle::validate_owned_backing(caps.pml4)?;
    let _borrow = Borrow::acquire()?;
    let ledger = &mut *core::ptr::addr_of_mut!(LEDGER);
    if ledger.rows.iter().any(|row| {
        let old = row.owner.descriptor();
        old.pi == pi
            && (nt_memory_manager::MemoryLifetime::Process(old.process) != lifetime
                || old.pml4 != caps.pml4
                || row.retiring)
    }) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    if [Level::Pdpt, Level::Directory]
        .into_iter()
        .all(|level| initial_parent_at(caps, level, page & !(level.span() - 1)))
    {
        return Ok(());
    }
    let nt_memory_manager::MemoryLifetime::Process(process) = lifetime else {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    };
    let path = [Level::Pdpt, Level::Directory].map(|level| Descriptor {
        pi,
        process,
        pml4: caps.pml4,
        level,
        base: page & !(level.span() - 1),
    });
    if !spawn_process_is_current(path[0], caps) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    reserve_path(ledger, caps, path)?;
    for descriptor in path {
        if initial_parent(caps, descriptor) {
            continue;
        }
        let row = ledger
            .rows
            .iter_mut()
            .find(|row| *row.owner.descriptor() == descriptor)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        row.owner
            .construct(&mut Io {
                admission: Admission::Spawn(caps),
                descriptor,
                retyped: &mut row.retyped,
                charged: &mut row.charged,
            })
            .map_err(status)?;
    }
    Ok(())
}

pub(crate) unsafe fn ensure_process_user_paging_parents(
    handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    pml4: u64,
) -> Result<(), u32> {
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if page & 0xfff != 0 || page >= USER_ADDRESS_LIMIT || pml4 == 0 {
        return Err(nt_address_space::STATUS_INVALID_PARAMETER);
    }
    if handler.pm.process(process.pid).is_none_or(|process| {
        matches!(
            process.state,
            nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
        )
    }) {
        return Err(nt_process::STATUS_PROCESS_IS_TERMINATING);
    }
    let caps = handler
        .process_vspace_caps
        .get(pi)
        .copied()
        .flatten()
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let mechanism = handler
        .process_mechanisms
        .get(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if caps.generation != mechanism.generation || mechanism.pid != process.pid || caps.pml4 != pml4
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let path = [Level::Pdpt, Level::Directory].map(|level| Descriptor {
        pi,
        process,
        pml4,
        level,
        base: page & !(level.span() - 1),
    });
    if !current(handler, path[0]) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    // Initial MM registration accounts spawn-owned physical rows before borrowing this ledger.
    handler.ensure_process_commit_owner(process.pid, pi)?;
    let _borrow = Borrow::acquire()?;
    let ledger = &mut *core::ptr::addr_of_mut!(LEDGER);
    reserve_path(ledger, caps, path)?;
    for descriptor in path {
        if initial_parent(caps, descriptor) {
            continue;
        }
        let row = ledger
            .rows
            .iter_mut()
            .find(|row| *row.owner.descriptor() == descriptor)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        row.owner
            .construct(&mut Io {
                admission: Admission::Live(handler),
                descriptor,
                retyped: &mut row.retyped,
                charged: &mut row.charged,
            })
            .map_err(status)?;
    }
    Ok(())
}

/// Leaf tables and all image/private mappings must have retired before entering this function.
pub(crate) unsafe fn retire_process_user_paging_parents(
    handler: &mut ExecNtHandler,
    pi: usize,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let ledger = &mut *core::ptr::addr_of_mut!(LEDGER);
    if !ledger
        .rows
        .iter()
        .any(|row| row.owner.descriptor().pi == pi)
    {
        return Ok(());
    }
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let pml4 = handler
        .hosted_process_vspace(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if ledger.rows.iter().any(|row| {
        row.owner.descriptor().pi == pi
            && (row.owner.descriptor().process != process
                || row.owner.descriptor().pml4 != pml4
                || !current(handler, *row.owner.descriptor()))
    }) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    for row in ledger
        .rows
        .iter_mut()
        .filter(|row| row.owner.descriptor().pi == pi)
    {
        row.retiring = true;
    }
    for level in [Level::Directory, Level::Pdpt] {
        while let Some(index) = ledger.rows.iter().position(|row| {
            let descriptor = row.owner.descriptor();
            descriptor.pi == pi && descriptor.level == level
        }) {
            let row = &mut ledger.rows[index];
            let descriptor = *row.owner.descriptor();
            row.owner
                .retire(&mut Io {
                    admission: Admission::Live(handler),
                    descriptor,
                    retyped: &mut row.retyped,
                    charged: &mut row.charged,
                })
                .map_err(status)?;
            if !row.owner.is_released() {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            ledger.rows.swap_remove(index);
        }
    }
    Ok(())
}

pub(crate) unsafe fn process_commit_bytes(pi: usize) -> u64 {
    let _borrow =
        Borrow::acquire().expect("paging accounting must precede the mutable ledger borrow");
    (&*core::ptr::addr_of!(LEDGER))
        .rows
        .iter()
        .filter(|row| row.owner.descriptor().pi == pi && row.retyped)
        .count() as u64
        * 4096
}

pub(crate) fn spawn_process_available(pi: usize) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe {
        !(&*core::ptr::addr_of!(LEDGER))
            .rows
            .iter()
            .any(|row| row.owner.descriptor().pi == pi)
    }
}

/// Called only after initial MM and job registration ACKs, without native effects or callbacks.
pub(crate) unsafe fn mark_process_accounted(
    handler: &ExecNtHandler,
    pi: usize,
    caps: HostedProcessVspaceCaps,
) {
    let _borrow =
        Borrow::acquire().expect("initial accounting cannot reenter a borrowed paging owner");
    let ledger = &mut *core::ptr::addr_of_mut!(LEDGER);
    for row in ledger
        .rows
        .iter_mut()
        .filter(|row| row.owner.descriptor().pi == pi)
    {
        assert!(
            handler.capture_process_identity(pi) == Some(row.owner.descriptor().process)
                && spawn_process_is_current(*row.owner.descriptor(), caps),
            "initial charge ACK changed paging identity"
        );
        row.charged = row.retyped;
    }
}

pub(crate) fn stats() -> Option<(usize, usize, u64, u64)> {
    let _borrow = Borrow::acquire().ok()?;
    unsafe {
        let ledger = &*core::ptr::addr_of!(LEDGER);
        Some((
            ledger.rows.len(),
            ledger.rows.capacity(),
            ledger.growths,
            ledger.allocation_failures,
        ))
    }
}
