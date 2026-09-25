//! Component-local FILE_OBJECT publication and independently retained teardown.

use super::*;
use nt_driver_runtime::{decode_file_projection_reply, FileProjectionSlot};

struct Row {
    projection: FileProjectionSlot,
    in_flight: bool,
}

struct FileObjectStore {
    rows: Vec<Option<Row>>,
    next_retirement: usize,
}

const _: () = assert!(core::mem::size_of::<FileObjectStore>() <= 0x40);
const RETIREMENT_BUDGET: usize = 16;
const FILE_NAME_BUFFER_OFFSET: u64 = 0x60;

pub(super) unsafe fn free_file_storage(file_object: u64) {
    let name = read_unaligned((file_object + FILE_NAME_BUFFER_OFFSET) as *const u64);
    if name != 0 && component_pool_allocation_capacity(name).is_some() {
        pool_free(name);
    }
    pool_free(file_object);
}

unsafe fn store() -> &'static mut FileObjectStore {
    &mut *((FSD_DATA_VADDR + FSD_DATA_FILE_OBJECT_STORE_OFF) as *mut FileObjectStore)
}

pub(super) unsafe fn initialize() {
    core::ptr::write(
        (FSD_DATA_VADDR + FSD_DATA_FILE_OBJECT_STORE_OFF) as *mut FileObjectStore,
        FileObjectStore {
            rows: Vec::new(),
            next_retirement: 0,
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
pub(super) unsafe fn fo_register(file: u64, address: u64) -> bool {
    if index_for_file(file).is_some() || !fo_reserve_new_slot() {
        return false;
    }
    let Some(projection) = FileProjectionSlot::new(file, address) else {
        return false;
    };
    let row = Some(Row {
        projection,
        in_flight: false,
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

pub(super) unsafe fn fo_bind(file: u64, irp: u64) -> Result<(), i32> {
    let index = index_for_file(file).ok_or(STATUS_INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    if row.in_flight || row.projection.is_live() || row.projection.is_retiring() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let snapshot = row.projection;
    row.in_flight = true;
    let reply = service(1, irp, snapshot);
    let row = rows_mut()[index]
        .as_mut()
        .expect("in-flight File publication lost its owner");
    row.in_flight = false;
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
    row.in_flight = true;
    let mut snapshot = row.projection;
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
    row.in_flight = false;
    if !retired || row.projection != snapshot {
        return false;
    }
    rows_mut()[index] = None;
    free_file_storage(snapshot.address());
    publish_retirements();
    true
}

/// One bounded, rotating pass. Failed acknowledgements retain their exact allocation and receipt.
pub(super) unsafe fn drain() -> u64 {
    let count = rows().len();
    if count == 0 {
        return 0;
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
    retired
}
