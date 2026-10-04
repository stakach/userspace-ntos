//! A registry observation must return resource failure rather than abort the executive.
//! Subprocesses contain the old infallible allocation's abort so the suite can report RED.

use nt_config_abi::{
    opcode, CmReply, CM_HIVE_KEY_SNAPSHOT_MAGIC, CM_HIVE_KEY_SNAPSHOT_VERSION,
    CM_OPTIONAL_STRING_ABSENT,
};
use nt_config_client::{Backend, ConfigClient};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::process::Command;

const PATH: &str = r"\Registry\Machine\SYSTEM\Setup";
const BLOB_BYTES: usize = 53;
const INSUFFICIENT_RESOURCES: i32 = 0xc000_009au32 as i32;
const CHILD_ENV: &str = "NT_CONFIG_QUERY_ALLOCATION_REFUSAL_CASE";

std::thread_local! {
    static FAIL_SIZE: Cell<usize> = const { Cell::new(0) };
    static REFUSALS: Cell<usize> = const { Cell::new(0) };
}

struct RefusingAllocator;

fn refuse(size: usize) -> bool {
    FAIL_SIZE
        .try_with(|target| {
            if target.get() == 0 || target.get() != size {
                return false;
            }
            target.set(0);
            REFUSALS.with(|count| count.set(count.get() + 1));
            true
        })
        .unwrap_or(false)
}

// SAFETY: Successful operations and all deallocations retain System's allocation contract.
// The sole injected failure is a null allocation result, which GlobalAlloc permits.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: Forward the caller's valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: Forward the caller's valid allocation layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if refuse(new_size) {
            return std::ptr::null_mut();
        }
        // SAFETY: Every non-null allocation came from System; its layout is unchanged.
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: Every non-null allocation came from System with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;

struct CompleteSnapshot<'a> {
    bytes: &'a [u8],
    calls: &'a Cell<usize>,
}

impl Backend for CompleteSnapshot<'_> {
    fn call(&mut self, operation: u16, _: &[u8], output: &mut [u8]) -> CmReply {
        assert_eq!(operation, opcode::CM_OP_QUERY_HIVE_KEY);
        self.calls.set(self.calls.get() + 1);
        output[..self.bytes.len()].copy_from_slice(self.bytes);
        CmReply {
            status: 0,
            information: self.bytes.len() as u32,
            detail0: self.bytes.len() as u64,
            detail1: 0,
        }
    }
}

fn snapshot(subkeys: u32, values: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&CM_HIVE_KEY_SNAPSHOT_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&CM_HIVE_KEY_SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&7u64.to_le_bytes());
    bytes.extend_from_slice(&subkeys.to_le_bytes());
    bytes.extend_from_slice(&values.to_le_bytes());
    bytes.extend_from_slice(&(PATH.len() as u32).to_le_bytes());
    bytes.extend_from_slice(PATH.as_bytes());
    bytes.extend_from_slice(&CM_OPTIONAL_STRING_ABSENT.to_le_bytes());
    bytes.extend_from_slice(&(BLOB_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(&[0x5a; BLOB_BYTES]);
    for index in 0..subkeys {
        let name = format!("Subkey{index}");
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&CM_OPTIONAL_STRING_ABSENT.to_le_bytes());
    }
    for index in 0..values {
        let name = format!("Value{index}");
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes()); // REG_BINARY.
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
    }
    bytes
}

fn run_case(test: &str, allocation_size: usize, expected_calls: usize, subkeys: u32, values: u32) {
    if std::env::var(CHILD_ENV).as_deref() != Ok(test) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, test)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "query allocation refusal must return normally: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let bytes = snapshot(subkeys, values);
    let calls = Cell::new(0);
    let mut client = ConfigClient::new(CompleteSnapshot {
        bytes: &bytes,
        calls: &calls,
    });
    let baseline = client.query_system_hive_key(PATH).unwrap();
    assert_eq!(baseline.mount_generation, 7);
    assert_eq!(baseline.path, PATH);
    assert_eq!(
        baseline.security_descriptor.as_deref(),
        Some(&[0x5a; BLOB_BYTES][..])
    );
    assert_eq!(baseline.subkeys.len(), subkeys as usize);
    assert_eq!(baseline.values.len(), values as usize);
    drop(baseline);
    calls.set(0);
    REFUSALS.with(|count| count.set(0));
    FAIL_SIZE.with(|target| target.set(allocation_size));
    let result = client.query_system_hive_key(PATH);
    FAIL_SIZE.with(|target| target.set(0));

    assert_eq!(
        REFUSALS.with(Cell::get),
        1,
        "fixture must exercise the intended allocation"
    );
    assert_eq!(calls.get(), expected_calls);
    assert_eq!(result, Err(INSUFFICIENT_RESOURCES));
}

#[test]
fn query_path_allocation_refusal_returns_resources_without_ipc() {
    run_case(
        "query_path_allocation_refusal_returns_resources_without_ipc",
        PATH.encode_utf16().count() * 2,
        0,
        0,
        0,
    );
}

#[test]
fn query_snapshot_string_allocation_refusal_returns_resources() {
    run_case(
        "query_snapshot_string_allocation_refusal_returns_resources",
        PATH.len(),
        1,
        0,
        0,
    );
}

#[test]
fn query_snapshot_blob_allocation_refusal_returns_resources() {
    run_case(
        "query_snapshot_blob_allocation_refusal_returns_resources",
        BLOB_BYTES,
        1,
        0,
        0,
    );
}

#[test]
fn query_snapshot_subkey_metadata_allocation_refusal_returns_resources() {
    run_case(
        "query_snapshot_subkey_metadata_allocation_refusal_returns_resources",
        3 * std::mem::size_of::<nt_config_client::HiveSubkeySnapshot>(),
        1,
        3,
        0,
    );
}

#[test]
fn query_snapshot_value_metadata_allocation_refusal_returns_resources() {
    run_case(
        "query_snapshot_value_metadata_allocation_refusal_returns_resources",
        3 * std::mem::size_of::<nt_config_client::HiveValueSnapshot>(),
        1,
        0,
        3,
    );
}

#[test]
fn query_snapshot_malformed_string_remains_invalid_parameter() {
    let mut bytes = snapshot(0, 0);
    // The first string follows the 24-byte header and its four-byte byte length.
    bytes[28] = 0xff;
    let calls = Cell::new(0);
    let mut client = ConfigClient::new(CompleteSnapshot {
        bytes: &bytes,
        calls: &calls,
    });
    assert_eq!(
        client.query_system_hive_key(PATH),
        Err(0xc000_000du32 as i32)
    );
    assert_eq!(calls.get(), 1);
}
