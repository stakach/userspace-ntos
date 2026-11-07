//! Component-local FILE_OBJECT publication and independently retained teardown.

use super::*;
use nt_driver_runtime::{decode_file_projection_reply, FileProjectionSlot};

struct Row {
    projection: FileProjectionSlot,
    in_flight: bool,
    storage_retirement_attempted: bool,
    storage_physically_retired: bool,
    canonical_unbound: bool,
    constructor_name: u64,
    file_generation: u64,
    name_generation: u64,
}

struct FileObjectStore {
    rows: Vec<Option<Row>>,
    retired_constructors: Vec<CreatedFileStorage>,
    next_retirement: usize,
    next_constructor_retirement: usize,
}

const _: () = assert!(core::mem::size_of::<FileObjectStore>() <= 0x40);
const RETIREMENT_BUDGET: usize = 16;
const FILE_NAME_BUFFER_OFFSET: u64 = 0x60;
static CREATED_FILE_LOCK: AtomicU64 = AtomicU64::new(0);

struct CreatedFileGuard;
impl Drop for CreatedFileGuard {
    fn drop(&mut self) { CREATED_FILE_LOCK.store(0, Ordering::Release); }
}
fn lock_created_files() -> CreatedFileGuard {
    while CREATED_FILE_LOCK.compare_exchange_weak(
        0, 1, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() {
        crate::yield_now();
    }
    CreatedFileGuard
}

#[derive(Clone, Copy)]
pub(super) struct CreatedFileStorage {
    pub(super) file: u64,
    pub(super) file_generation: u64,
    pub(super) name: u64,
    pub(super) name_generation: u64,
    pub(super) name_released: bool,
    pub(super) file_released: bool,
}

/// Capture the two constructor allocations before any provider callback can rewrite FileName.
pub(super) unsafe fn capture_created_file_storage(file: u64) -> Option<CreatedFileStorage> {
    component_pool_allocation_capacity(file)?;
    let name = read_unaligned((file + FILE_NAME_BUFFER_OFFSET) as *const u64);
    if name == 0 || name == file {
        return None;
    }
    component_pool_allocation_capacity(name)?;
    let file_generation = component_pool_allocation_generation(file)?;
    let name_generation = component_pool_allocation_generation(name)?;
    Some(CreatedFileStorage {
        file, file_generation, name, name_generation,
        name_released: false, file_released: false,
    })
}

pub(super) unsafe fn free_file_storage(storage: &mut CreatedFileStorage) -> bool {
    if !storage.name_released {
        if component_pool_allocation_generation(storage.name) != Some(storage.name_generation)
            || !pool_free_exact(storage.name, storage.name_generation)
        {
            return false;
        }
        storage.name_released = true;
    }
    if !storage.file_released {
        if component_pool_allocation_generation(storage.file) != Some(storage.file_generation)
            || !pool_free_exact(storage.file, storage.file_generation)
        {
            return false;
        }
        storage.file_released = true;
    }
    true
}

/// Transfer an unpublished constructor owner before any local free. A partial definite refusal
/// stays in this store and retries only the remaining exact generation on later drain passes.
pub(super) unsafe fn retire_created_file_storage(storage: CreatedFileStorage) -> bool {
    let _durable = crate::allocator::enter_durable();
    let _guard = lock_created_files();
    let retained = &mut store().retired_constructors;
    if retained.try_reserve(1).is_err() {
        crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_FILE_LABEL, 9, storage.file, storage.file_generation],
        );
    }
    retained.push(storage);
    drain_created_file_storage_unlocked() != 0
}

unsafe fn drain_created_file_storage() -> u64 {
    let _guard = lock_created_files();
    drain_created_file_storage_unlocked()
}

unsafe fn drain_created_file_storage_unlocked() -> u64 {
    let state = store();
    drain_created_file_storage_rows(
        &mut state.retired_constructors,
        &mut state.next_constructor_retirement,
    )
}

pub(super) unsafe fn drain_created_file_storage_rows(
    retained: &mut Vec<CreatedFileStorage>, next: &mut usize,
) -> u64 {
    if retained.is_empty() { return 0; }
    let mut index = *next % retained.len();
    let mut retired = 0;
    let mut scanned = 0;
    let initial = retained.len();
    while scanned < initial && scanned < RETIREMENT_BUDGET && !retained.is_empty() {
        scanned += 1;
        if free_file_storage(&mut retained[index]) {
            retained.swap_remove(index);
            retired += 1;
            if !retained.is_empty() { index %= retained.len(); }
        } else {
            index = (index + 1) % retained.len();
        }
    }
    *next = index;
    retired
}

unsafe fn store() -> &'static mut FileObjectStore {
    &mut *((FSD_DATA_VADDR + FSD_DATA_FILE_OBJECT_STORE_OFF) as *mut FileObjectStore)
}

pub(super) unsafe fn initialize() {
    core::ptr::write(
        (FSD_DATA_VADDR + FSD_DATA_FILE_OBJECT_STORE_OFF) as *mut FileObjectStore,
        FileObjectStore {
            rows: Vec::new(),
            retired_constructors: Vec::new(),
            next_retirement: 0,
            next_constructor_retirement: 0,
        },
    );
}

unsafe fn rows() -> &'static Vec<Option<Row>> {
    &store().rows
}

unsafe fn rows_mut() -> &'static mut Vec<Option<Row>> {
    &mut store().rows
}

unsafe fn index_for_file(file: u64) -> Option<usize> {
    rows().iter().position(|row| {
        row.as_ref()
            .is_some_and(|row| row.projection.file_id() == file)
    })
}

pub(super) unsafe fn fo_lookup(file: u64) -> u64 {
    index_for_file(file)
        .and_then(|index| rows()[index].as_ref())
        .filter(|row| row.projection.is_live())
        .map_or(0, |row| row.projection.address())
}

pub(super) unsafe fn fo_is_registered(address: u64) -> bool {
    rows()
        .iter()
        .flatten()
        .any(|row| row.projection.is_live() && row.projection.address() == address)
}

pub(super) unsafe fn fo_reserve_new_slot() -> bool {
    if rows().iter().any(Option::is_none) || rows().len() < rows().capacity() {
        return true;
    }
    if rows_mut().try_reserve(1).is_ok() {
        true
    } else {
        FSD_FO_TABLE_EXHAUSTED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Reserve local ownership before IPC. The caller then transfers the IRP's allocation owner here.
pub(super) unsafe fn fo_register(file: u64, storage: CreatedFileStorage) -> bool {
    let address = storage.file;
    if index_for_file(file).is_some() || !fo_reserve_new_slot() {
        return false;
    }
    let Some(projection) = FileProjectionSlot::new(file, address) else {
        return false;
    };
    if component_pool_allocation_generation(address) != Some(storage.file_generation)
        || component_pool_allocation_generation(storage.name) != Some(storage.name_generation)
    {
        return false;
    }
    let row = Some(Row {
        projection,
        in_flight: false,
        storage_retirement_attempted: false,
        storage_physically_retired: false,
        canonical_unbound: false,
        constructor_name: storage.name,
        file_generation: storage.file_generation,
        name_generation: storage.name_generation,
    });
    if let Some(index) = rows().iter().position(Option::is_none) {
        rows_mut()[index] = row;
    } else {
        rows_mut().push(row);
    }
    true
}

unsafe fn service(
    op: u64,
    request: u64,
    projection: FileProjectionSlot,
) -> Option<Result<u64, i32>> {
    let (info, status, generation, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_FILE_LABEL << 12) | 4,
        op,
        request,
        projection.file_id(),
        projection.address(),
    );
    decode_file_projection_reply(info, status, generation, [reserved0, reserved1], op)
}

pub(super) unsafe fn retire_file_storage_result(file: u64, address: u64) -> Option<Result<(), i32>> {
    let (words, status, value, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_FILE_LABEL << 12) | 4,
        9,
        0,
        file,
        address,
    );
    if words != 4 || status > u32::MAX as u64 || value != 0 || reserved0 != 0 || reserved1 != 0 {
        return None;
    }
    let status = status as u32 as i32;
    Some(if status == STATUS_SUCCESS { Ok(()) } else { Err(status) })
}

unsafe fn file_storage_disposition(file: u64, address: u64, generation: u64) -> Option<u64> {
    let (words, status, flags, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_FILE_LABEL << 12) | 4,
        10,
        generation,
        file,
        address,
    );
    (words == 4 && status as u32 as i32 == STATUS_SUCCESS
        && flags <= 3 && reserved0 == 0 && reserved1 == 0).then_some(flags)
}

unsafe fn acknowledge_file_storage(file: u64, address: u64, generation: u64) -> bool {
    let (words, status, value, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_FILE_LABEL << 12) | 4,
        11,
        generation,
        file,
        address,
    );
    words == 4 && status as u32 as i32 == STATUS_SUCCESS
        && value == 0 && reserved0 == 0 && reserved1 == 0
}

pub(super) fn pre_entry_no_root_owner(
    words: u64, status: u64, generation: u64, reserved0: u64, reserved1: u64,
) -> bool {
    words == 4 && status <= u32::MAX as u64
        && (status as u32 as i32) < 0 && generation == 0
        && reserved0 == 1 && reserved1 == 0
}

pub(super) unsafe fn fo_bind(file: u64, irp: u64) -> Result<(), i32> {
    let index = index_for_file(file).ok_or(STATUS_INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    if row.in_flight || row.projection.is_live() || row.projection.is_retiring() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let snapshot = row.projection;
    row.in_flight = true;
    let (words, status, generation, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_FILE_LABEL << 12) | 4,
        1,
        irp,
        snapshot.file_id(),
        snapshot.address(),
    );
    let no_root_owner = pre_entry_no_root_owner(words, status, generation, reserved0, reserved1);
    let reply = if no_root_owner {
        Some(Err(status as u32 as i32))
    } else {
        decode_file_projection_reply(words, status, generation, [reserved0, reserved1], 1)
    };
    let row = rows_mut()[index]
        .as_mut()
        .expect("in-flight File publication lost its owner");
    row.in_flight = false;
    if no_root_owner {
        let storage = CreatedFileStorage {
            file: snapshot.address(), file_generation: row.file_generation,
            name: row.constructor_name, name_generation: row.name_generation,
            name_released: false, file_released: false,
        };
        retire_created_file_storage(storage);
        rows_mut()[index] = None;
        return Err(status as u32 as i32);
    }
    match reply {
        Some(Ok(generation)) if row.projection.publish(snapshot, generation) => {
            FSD_FO_OPENS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        _ => {
            // A malformed reply may follow a successful bind. Resolve it through QUERY while
            // retaining the allocation; never infer that a missing receipt means no publication.
            row.projection.retire();
            publish_retirements();
            Err(reply.and_then(Result::err).unwrap_or(STATUS_UNSUCCESSFUL))
        }
    }
}

unsafe fn publish_retirements() {
    let count = rows()
        .iter()
        .flatten()
        .filter(|row| row.projection.is_retiring())
        .count();
    write_volatile(
        (FSD_SHARED_VADDR + SH_FILE_RETIREMENTS) as *mut u64,
        count as u64,
    );
}

/// CLOSE/failed CREATE transfers storage here before the unrelated IRP graph is reclaimed.
pub(super) unsafe fn fo_release(file: u64) {
    let Some(index) = index_for_file(file) else {
        return;
    };
    rows_mut()[index].as_mut().unwrap().projection.retire();
    publish_retirements();
    retire_one(index);
}

unsafe fn retire_one(index: usize) -> bool {
    let Some(row) = rows_mut().get_mut(index).and_then(Option::as_mut) else {
        return false;
    };
    if !row.projection.is_retiring() || row.in_flight {
        return false;
    }
    if row.storage_retirement_attempted {
        return finish_file_storage_retirement(index);
    }
    row.in_flight = true;
    let mut snapshot = row.projection;
    if !row.canonical_unbound {
        let mut absent = false;
        if snapshot.generation() == 0 {
            let reply = service(3, 0, snapshot);
            let row = rows_mut()[index]
                .as_mut()
                .expect("in-flight File retirement lost its owner");
            match reply {
                Some(Ok(generation)) if row.projection.resolve_retirement(snapshot, generation) => {
                    absent = generation == 0;
                    snapshot = row.projection;
                }
                _ => {
                    row.in_flight = false;
                    return false;
                }
            }
        }
        let retired = absent || matches!(service(2, snapshot.generation(), snapshot), Some(Ok(0)));
        let row = rows_mut()[index]
            .as_mut()
            .expect("in-flight File retirement lost its owner");
        if !retired || row.projection != snapshot {
            row.in_flight = false;
            return false;
        }
        row.canonical_unbound = true;
    }
    let row = rows_mut()[index]
        .as_mut()
        .expect("in-flight File retirement lost its owner");
    row.in_flight = false;
    // The root captured the constructor's two physical allocations before driver entry.
    // Claim a single broker attempt before IPC: an ambiguous reply cannot authorize replay.
    row.storage_retirement_attempted = true;
    match retire_file_storage_result(snapshot.file_id(), snapshot.address()) {
        Some(Ok(())) => row.storage_physically_retired = true,
        Some(Err(_)) => {
            // A definite refusal has completed at the root. Its per-member receipts make a
            // later attempt safe, even if the name was already released before the refusal.
            row.storage_retirement_attempted = false;
            return false;
        }
        None => {}
    }
    finish_file_storage_retirement(index)
}

unsafe fn finish_file_storage_retirement(index: usize) -> bool {
    let Some(row) = rows_mut().get_mut(index).and_then(Option::as_mut) else {
        return false;
    };
    if !row.storage_physically_retired {
        if file_storage_disposition(
            row.projection.file_id(), row.projection.address(), row.file_generation,
        ) != Some(3) {
            return false;
        }
        row.storage_physically_retired = true;
    }
    let file = row.projection.file_id();
    let address = row.projection.address();
    let generation = row.file_generation;
    if !acknowledge_file_storage(file, address, generation)
        && !acknowledge_file_storage(file, address, generation)
    {
        return false;
    }
    rows_mut()[index] = None;
    publish_retirements();
    true
}

/// One bounded, rotating pass. Failed acknowledgements retain their exact allocation and receipt.
pub(super) unsafe fn drain() -> u64 {
    let constructor_retired = drain_created_file_storage();
    let count = rows().len();
    if count == 0 {
        return constructor_retired;
    }
    let mut retired = 0;
    let start = store().next_retirement % count;
    let mut scanned = 0;
    let mut attempted = 0;
    while scanned < count && attempted < RETIREMENT_BUDGET {
        let index = (start + scanned) % count;
        scanned += 1;
        if rows()[index]
            .as_ref()
            .is_some_and(|row| row.projection.is_retiring() && !row.in_flight)
        {
            attempted += 1;
            retired += u64::from(retire_one(index));
        }
    }
    store().next_retirement = (start + scanned) % count;
    publish_retirements();
    retired + constructor_retired
}
