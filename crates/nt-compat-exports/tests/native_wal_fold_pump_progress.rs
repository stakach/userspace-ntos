//! Execute the native receive-boundary fold decision with a durable retry still due.
//! A no-op or deferred attempt must let the pump receive other work instead of spinning.

use std::process::Command;

#[test]
fn fold_receive_boundary_continues_only_after_consuming_due_work() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let record_start = service.find("pub(crate) fn record_due_system_wal_fold(").unwrap();
    let record_end = record_start + service[record_start..]
        .find("\n}\n\npub(crate) fn system_wal_fold_work_pending()")
        .expect("native timer admission") + 2;
    let record = &service[record_start..record_end];
    syn::parse_str::<syn::ItemFn>(record).expect("actual native timer admission");
    let pending_start = service.find("pub(crate) fn system_wal_fold_work_pending()").unwrap();
    let pending_end = pending_start + service[pending_start..]
        .find("\n}\n\n/// Enter the same physical fold contract")
        .expect("native receive eligibility") + 2;
    let pending = &service[pending_start..pending_end];
    syn::parse_str::<syn::ItemFn>(pending).expect("actual native receive eligibility");
    let start = service.find("pub(crate) fn service_due_system_wal_fold()").unwrap();
    let end = start + service[start..].find("\n}\n\n/// Coalesce CM-owned SYSTEM mutations")
        .expect("native fold boundary") + 2;
    let rule = &service[start..end];
    syn::parse_str::<syn::ItemFn>(rule).expect("actual native fold decision");
    let harness = format!(r#"
use std::sync::atomic::{{AtomicBool, AtomicU64, AtomicU8, Ordering}};
const SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS: u64 = 1000;
static SYSTEM_WAL_FOLD_DUE: AtomicBool = AtomicBool::new(false);
static SYSTEM_WAL_FOLD_READY: AtomicBool = AtomicBool::new(false);
static SYSTEM_WAL_FOLD_RUNNING: AtomicBool = AtomicBool::new(false);
static SYSTEM_WAL_FOLD_RETRY_100NS: AtomicU64 = AtomicU64::new(0);
static IDLE: AtomicBool = AtomicBool::new(true);
static OUTCOME: AtomicU8 = AtomicU8::new(0);
fn config_manager_channel_idle() -> bool {{ IDLE.load(Ordering::Acquire) }}
fn system_wal_fold_next_deadline() -> Option<u64> {{
    if SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire) {{
        Some(SYSTEM_WAL_FOLD_RETRY_100NS.load(Ordering::Acquire))
    }} else {{ Some(100) }}
}}
fn maybe_fold_system_wal() -> Result<(), u32> {{
    match OUTCOME.load(Ordering::Acquire) {{
        0 => Ok(()), // busy or below cadence: durable retry remains due
        1 => {{ SYSTEM_WAL_FOLD_DUE.store(false, Ordering::Release); Ok(()) }},
        _ => Err(0xc000_0001),
    }}
}}
{record}
{pending}
{rule}
#[test] fn pump_progress() {{
    assert_eq!(record_due_system_wal_fold(100), 1);
    assert!(system_wal_fold_work_pending());
    OUTCOME.store(0, Ordering::Release);
    assert_eq!(service_due_system_wal_fold(), Ok(false), "pending retry cannot spin Receive");
    assert!(SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire));
    assert!(!SYSTEM_WAL_FOLD_RUNNING.load(Ordering::Acquire));
    assert!(!system_wal_fold_work_pending());
    assert_eq!(record_due_system_wal_fold(101), 0);
    assert!(!system_wal_fold_work_pending());

    assert_eq!(record_due_system_wal_fold(1100), 1);
    assert!(system_wal_fold_work_pending());

    OUTCOME.store(1, Ordering::Release);
    assert_eq!(service_due_system_wal_fold(), Ok(true), "consumed fold can take one more pump pass");
    assert!(!SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire));

    SYSTEM_WAL_FOLD_DUE.store(true, Ordering::Release);
    SYSTEM_WAL_FOLD_READY.store(true, Ordering::Release);
    OUTCOME.store(2, Ordering::Release);
    assert_eq!(service_due_system_wal_fold(), Err(0xc000_0001));
    assert!(!SYSTEM_WAL_FOLD_RUNNING.load(Ordering::Acquire));
    assert!(!system_wal_fold_work_pending());

    SYSTEM_WAL_FOLD_READY.store(true, Ordering::Release);
    IDLE.store(false, Ordering::Release);
    assert_eq!(service_due_system_wal_fold(), Ok(false));
}}
"#);
    let directory = std::env::temp_dir().join(format!("nt-wal-fold-pump-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&source, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native fold compile: {}",
        String::from_utf8_lossy(&compiled.stderr));
    let run = Command::new(&binary).output().unwrap();
    assert!(run.status.success(), "native fold behavior: {}",
        String::from_utf8_lossy(&run.stdout));
}
