//! Run the native interrupt adapters against distinct primary and worker device banks.

use std::process::Command;

#[test]
fn interrupt_connection_and_retirement_use_the_calling_lanes_resource_bank() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("extern \"win64\" fn s_io_connect_interrupt(")
        .expect("native IoConnectInterrupt adapter");
    let end = source[start..]
        .find("\n/// `PDMA_ADAPTER IoGetDmaAdapter")
        .expect("native interrupt adapter boundary");
    let ex = include_str!("../../../components/ntos-executive/src/hosted_driver_interrupt_ex.rs");
    let publication = include_str!(
        "../../../components/ntos-executive/src/hosted_device_publication_decision.rs"
    );
    let adapter = |body: &str| {
        // The host does not support the guest ABI or fixed component VA. Resolve only those
        // two deployment details, so every bank read/write remains from the real adapters.
        body.replace("extern \"win64\" fn", "fn")
            .replace("FSD_SHARED_VADDR", "primary_bank()")
    };
    let fixture = format!(
        "{SUPPORT}\nmod hosted_device_publication_decision {{\n{publication}\n}}\n{}\n{}\n{CASES}",
        adapter(&source[start..start + end]),
        adapter(
            &ex.replace("//! Driver-local", "/// Driver-local")
                .replace("use super::*;", "")
                .replace("pub(super)", "pub")
        )
    );
    let directory =
        std::env::temp_dir().join(format!("nt-interrupt-worker-bank-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "interrupt fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "worker interrupt bank regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use std::sync::atomic::{AtomicU64, Ordering};

const SH_RESOURCE_PDO_OBJECT: u64 = 0;
const SH_RESOURCE_INTERRUPT_VECTOR: u64 = 8;
const SH_RESOURCE_INTERRUPT_AFFINITY: u64 = 16;
const SH_RESOURCE_INTERRUPT_POLICY: u64 = 24;
const SH_RESOURCE_INTERRUPT_OBJECT: u64 = 32;
const SH_RESOURCE_INTERRUPT_ROUTINE: u64 = 40;
const SH_RESOURCE_INTERRUPT_CONTEXT: u64 = 48;
const SH_RESOURCE_INTERRUPT_ID: u64 = 56;
const SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR: u64 = 64;
const SH_RESOURCE_INTERRUPT_ISR_CLAIMED: u64 = 72;
const SH_RESOURCE_INTERRUPT_DELIVERIES: u64 = 80;

const HOSTED_KINTERRUPT_VECTOR: u64 = 0;
const HOSTED_KINTERRUPT_IRQL: u64 = 8;
const HOSTED_KINTERRUPT_SYNCHRONIZE_IRQL: u64 = 9;
const HOSTED_KINTERRUPT_MODE: u64 = 10;
const HOSTED_KINTERRUPT_SHARE: u64 = 11;
const HOSTED_KINTERRUPT_ROUTINE: u64 = 16;
const HOSTED_KINTERRUPT_CONTEXT: u64 = 24;
const HOSTED_KINTERRUPT_ACTUAL_LOCK: u64 = 32;
const HOSTED_KINTERRUPT_AFFINITY: u64 = 40;
const HOSTED_KINTERRUPT_MAGIC_OFF: u64 = 48;
const HOSTED_KINTERRUPT_FLOATING_SAVE: u64 = 56;
const HOSTED_KINTERRUPT_ID: u64 = 64;
const HOSTED_KINTERRUPT_GRANT_GENERATION: u64 = 72;
const HOSTED_KINTERRUPT_PRIVATE_LOCK: u64 = 80;
const HOSTED_KINTERRUPT_MAGIC: u64 = 0x434f4e4e454354;
const FSD_SERVICE_INTERRUPT_LABEL: u64 = 0x736;
const HOSTED_INTERRUPT_OP_PROVISION: u64 = 0;
const HOSTED_INTERRUPT_OP_CONNECT: u64 = 1;
const HOSTED_INTERRUPT_OP_DISCONNECT: u64 = 2;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xc000000du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xc0000010u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xc00000bbu32 as i32;

static PRIMARY: AtomicU64 = AtomicU64::new(0);
static CURRENT: AtomicU64 = AtomicU64::new(0);
static PROJECTION: AtomicU64 = AtomicU64::new(0);
static ROOT_CALLS: AtomicU64 = AtomicU64::new(0);
static LAST_DISCONNECT: AtomicU64 = AtomicU64::new(0);

fn primary_bank() -> u64 { PRIMARY.load(Ordering::Relaxed) }
fn hosted_component_resource_shared_va() -> u64 { CURRENT.load(Ordering::Relaxed) }

fn call_on4(_: u64, op: u64, object: u64, _: u64, _: u64) -> (u64, u64, u64, u64, u64) {
    ROOT_CALLS.fetch_add(1, Ordering::Relaxed);
    let sh = hosted_component_resource_shared_va();
    match op {
        HOSTED_INTERRUPT_OP_PROVISION => (0, 0, PROJECTION.load(Ordering::Relaxed), 7, 0),
        HOSTED_INTERRUPT_OP_CONNECT => {
            let projected = unsafe { read_volatile((sh + SH_RESOURCE_INTERRUPT_OBJECT) as *const u64) };
            let routine = unsafe { read_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *const u64) };
            let context = unsafe { read_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *const u64) };
            assert_eq!((object, projected, routine, context),
                (PROJECTION.load(Ordering::Relaxed), object, 0x1234, 0x5678),
                "component must stage the worker's callback in its own bank before CONNECT");
            (0, 0, 99, 7, 0)
        }
        HOSTED_INTERRUPT_OP_DISCONNECT => {
            LAST_DISCONNECT.store(object, Ordering::Relaxed);
            (0, 0, 0, 0, 0)
        }
        _ => panic!("unexpected interrupt service"),
    }
}

#[allow(clippy::too_many_arguments)]
fn trace_hosted_io_connect_interrupt(_: u64, _: u64, _: u64, _: u32, _: u32,
    _: u64, _: u64, _: u64, _: i32) {}
fn clear_dpc_diagnostics(sh: u64) {
    assert_eq!(sh, hosted_component_resource_shared_va());
}

mod provider_bugcheck {
    pub unsafe fn report(_: u32, _: [u64; 4]) -> ! { panic!("unexpected bugcheck") }
}

fn worker_disconnect_keeps_a_siblings_newer_shared_interrupt() {
    let mut worker = Box::new([0u64; 16]);
    CURRENT.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    let keyboard = 0x1000_e803_a10_u64;
    let mouse = 0x1000_e803_960_u64;
    worker[(SH_RESOURCE_INTERRUPT_OBJECT / 8) as usize] = mouse;
    worker[(SH_RESOURCE_INTERRUPT_ID / 8) as usize] = 12;
    LAST_DISCONNECT.store(0, Ordering::Relaxed);
    s_io_disconnect_interrupt(keyboard);
    assert_eq!(LAST_DISCONNECT.load(Ordering::Relaxed), keyboard);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_OBJECT / 8) as usize], mouse);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_ID / 8) as usize], 12);
}
"#;

const CASES: &str = r#"
#[test]
fn worker_connect_disconnect_and_line_based_ex_stay_in_the_worker_bank() {
    let mut primary = Box::new([0u64; 16]);
    let mut worker = Box::new([0u64; 16]);
    let mut projection = Box::new([0u64; 16]);
    PRIMARY.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    CURRENT.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    PROJECTION.store(projection.as_mut_ptr() as u64, Ordering::Relaxed);
    primary[(SH_RESOURCE_PDO_OBJECT / 8) as usize] = 111;
    primary[(SH_RESOURCE_INTERRUPT_VECTOR / 8) as usize] = 0x40;
    primary[(SH_RESOURCE_INTERRUPT_AFFINITY / 8) as usize] = 1;
    primary[(SH_RESOURCE_INTERRUPT_POLICY / 8) as usize] = 5 | (1 << 16);
    worker[(SH_RESOURCE_PDO_OBJECT / 8) as usize] = 222;
    worker[(SH_RESOURCE_INTERRUPT_VECTOR / 8) as usize] = 0x51;
    worker[(SH_RESOURCE_INTERRUPT_AFFINITY / 8) as usize] = 1;
    worker[(SH_RESOURCE_INTERRUPT_POLICY / 8) as usize] = 5 | (1 << 16);
    let primary_before = *primary;

    let mut connected = 0u64;
    let status = s_io_connect_interrupt(&mut connected, 0x1234, 0x5678, 0,
        0x51, 5, 5, 0, 1, 1, 0);
    assert_eq!(status, STATUS_SUCCESS, "worker must validate its own vector");
    assert_eq!(connected, PROJECTION.load(Ordering::Relaxed));
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_OBJECT / 8) as usize], connected);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_ROUTINE / 8) as usize], 0x1234);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_CONTEXT / 8) as usize], 0x5678);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_ID / 8) as usize], 99);
    assert_eq!(*primary, primary_before, "the parked primary bank is owned by another dispatch");

    let calls = ROOT_CALLS.load(Ordering::Relaxed);
    let mut rejected = 0u64;
    assert_eq!(s_io_connect_interrupt(&mut rejected, 0x1234, 0x5678, 0,
        0x40, 5, 5, 0, 1, 1, 0), STATUS_INVALID_PARAMETER);
    assert_eq!(ROOT_CALLS.load(Ordering::Relaxed), calls,
        "a request mismatched with the worker grant must stop before PROVISION");
    assert_eq!(*primary, primary_before);

    s_io_disconnect_interrupt(connected);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_OBJECT / 8) as usize], 0);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_ID / 8) as usize], 0);
    assert_eq!(*primary, primary_before);

    let mut line_connected = 0u64;
    let line = ConnectParameters {
        version: CONNECT_LINE_BASED,
        fields: FullySpecified {
            pdo: 222, interrupt_object_out: (&mut line_connected as *mut u64) as u64,
            service_routine: 0x1234, service_context: 0x5678, spin_lock: 0,
            synchronize_irql: 0, floating_save: 0, share_vector: 0,
            vector: 0, irql: 0, mode: 0, affinity: 0, group: 0,
        },
    };
    assert_eq!(s_io_connect_interrupt_ex((&line as *const ConnectParameters) as u64), STATUS_SUCCESS);
    assert_eq!(line_connected, PROJECTION.load(Ordering::Relaxed));
    assert_eq!(*primary, primary_before);

    let disconnect = [CONNECT_LINE_BASED as u64, line_connected];
    s_io_disconnect_interrupt_ex(disconnect.as_ptr() as u64);
    assert_eq!(worker[(SH_RESOURCE_INTERRUPT_OBJECT / 8) as usize], 0);
    assert_eq!(*primary, primary_before);
    worker_disconnect_keeps_a_siblings_newer_shared_interrupt();
}
"#;
