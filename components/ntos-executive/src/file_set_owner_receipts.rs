//! Bounded receipts for exact SET delivery, including mounted provider work.
//!
//! Basic terminal admission is distinct from Reply publication, File release and row
//! retirement. Later stages use the same table/slot/generation/IRP key without a
//! trace-only owner or an inference from the guest's command output.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{print_str, print_u64};

const TRACE_LIMIT: u64 = 4096;
static TRACES: AtomicU64 = AtomicU64::new(0);

fn local_set(
    stage: &[u8],
    identity: nt_io_manager::PendingFileIoIdentity,
    row: nt_io_manager::PendingFileIo,
    status: u32,
    basic: Option<(u64, u32)>,
) {
    if row.major != nt_io_abi::major::IRP_MJ_SET_INFORMATION {
        return;
    }
    let file = match row.local_file_object() {
        Some(nt_io_manager::LocalFileObject::Overlay(file)) => file,
        _ => match row.hosted_file_id() {
            Some(file) => file,
            None => return,
        },
    };
    if TRACES.fetch_add(1, Ordering::Relaxed) >= TRACE_LIMIT {
        return;
    }
    print_str(b"[file-set-owner] stage=");
    print_str(stage);
    print_str(b" table=");
    print_u64(identity.table());
    print_str(b" slot=");
    print_u64(identity.slot() as u64);
    print_str(b" generation=");
    print_u64(identity.generation());
    print_str(b" irp=");
    print_u64(row.irp_id);
    print_str(b" pi=");
    print_u64(u64::from(row.pi));
    print_str(b" tid=");
    print_u64(row.tid);
    print_str(b" status=");
    print_u64(u64::from(status));
    print_str(b" file=");
    print_u64(file);
    if let Some((stable_file_id, attributes)) = basic {
        print_str(b" stable=");
        print_u64(stable_file_id);
        print_str(b" attrs=");
        print_u64(u64::from(attributes));
    }
    print_str(b"\n");
}

pub(crate) fn basic_terminal(
    identity: nt_io_manager::PendingFileIoIdentity,
    row: nt_io_manager::PendingFileIo,
    status: u32,
    stable_file_id: u64,
    input: &[u8; 40],
) {
    let attributes = u32::from_le_bytes(input[32..36].try_into().unwrap());
    local_set(b"basic-terminal", identity, row, status, Some((stable_file_id, attributes)));
}

pub(crate) fn reply(
    identity: nt_io_manager::PendingFileIoIdentity,
    row: nt_io_manager::PendingFileIo,
    status: u32,
) {
    local_set(b"reply", identity, row, status, None);
}

pub(crate) fn file_released(
    identity: nt_io_manager::PendingFileIoIdentity,
    row: nt_io_manager::PendingFileIo,
    status: u32,
) {
    local_set(b"file-released", identity, row, status, None);
}

pub(crate) fn retired(
    identity: nt_io_manager::PendingFileIoIdentity,
    row: nt_io_manager::PendingFileIo,
    status: u32,
) {
    local_set(b"retired", identity, row, status, None);
}
