//! Native SYSTEM fold keeps CM's exact preparation across preentry refusal and a proven
//! no-effect header abort (#8). Execute the production admission and abort arms with owned mocks.

use std::process::Command;

#[test]
fn native_fold_keeps_prepared_cm_owner_until_a_timer_can_retry() {
    let source = include_str!(
        "../../../components/ntos-executive/src/writable_fs/system_wal_fold/native.rs"
    );
    let begin_signature = "unsafe fn begin_recheck_with_prepared(";
    let begin = if let Some((_, tail)) = source.split_once(begin_signature) {
        let (body, _) = tail.split_once("\n}\n").expect("admission function boundary");
        format!("{begin_signature}{body}\n}}")
    } else {
        // The RED baseline transferred the lease before installing Work and let `?` drop CM's
        // local preparation. Execute that exact production statement with the same local owner.
        let old = "let id = snapshot_storage::begin_wal_continuation_recheck_with_lease(lease)?;";
        assert!(source.contains(old), "missing production fold admission");
        format!("unsafe fn begin_recheck_with_prepared(lease: snapshot_storage::Lease, \
            prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>, \
            _manifest: nt_fs::WalSnapshotManifest, _mount: SectionMountId) -> u32 {{\n\
            let _prepared = prepared;\n\
            let result = (|| -> Result<u64, u32> {{ {old} Ok(id) }})();\n\
            result.err().unwrap_or(0)\n}}")
    };
    let (_, advance) = source.split_once("unsafe fn advance_recheck()")
        .expect("production recheck continuation");
    let (advance, _) = advance.split_once("\n}\n").expect("recheck function boundary");
    let (_, abort) = advance.split_once("        Err(status) => {")
        .expect("production header refusal arm");
    let (abort, _) = abort.split_once("\n        }\n    };")
        .expect("header refusal arm boundary");
    let contradiction_start = "    if observed.incarnation != manifest.incarnation";
    let (_, contradiction) = source.split_once(contradiction_start)
        .expect("production retry manifest comparison");
    let (contradiction, _) = contradiction.split_once("\n    {")
        .expect("retry manifest comparison boundary");
    let contradiction = format!(
        "observed.incarnation != manifest.incarnation{contradiction}"
    );
    let fixture = format!(
        "{MOCKS}\n{begin}\nfn manifest_contradiction(observed: Manifest, manifest: Manifest) -> bool {{\n\
         {contradiction}\n}}\nfn failed_recheck(status: u32) -> Result<(), u32> {{\n\
         let slot = unsafe {{ &mut *core::ptr::addr_of_mut!(WORK) }};\n\
         let id = 7;\n{abort}\n    Err(status)\n}}\n{CASES}"
    );
    let dir = std::env::temp_dir().join(format!(
        "nt-retained-system-fold-admission-{}", std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("fixture.rs");
    let binary = dir.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "fold admission fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.status.success(), "fold admission regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
static PREPARED_DROPS: AtomicUsize = AtomicUsize::new(0);
static LEASE_DROPS: AtomicUsize = AtomicUsize::new(0);
static BEGIN_STATUS: AtomicU32 = AtomicU32::new(0x8000_0011);
static NO_EFFECT_ABORT: AtomicBool = AtomicBool::new(true);
static mut WORK: Option<Work> = None;
const ADMISSION_RETRY_100NS: u64 = 50_000_000;
type SectionMountId = u64;
struct Prepared;
impl Drop for Prepared { fn drop(&mut self) { PREPARED_DROPS.fetch_add(1, Ordering::AcqRel); } }
struct Lease;
impl Lease { fn identity(&self) -> &SectionMountId { &MOUNT } }
impl Drop for Lease { fn drop(&mut self) { LEASE_DROPS.fetch_add(1, Ordering::AcqRel); } }
const MOUNT: SectionMountId = 9;
#[derive(Clone, Copy)]
struct Manifest { incarnation: u64, base_serial: u64, high_water_serial: u64,
    high_water_end_lba: u64 }
enum StalledState { Admission { _lease: Option<Lease>, _prepared: Option<Prepared>,
    _mount: SectionMountId, _manifest: Manifest } }
enum Work {
    AdmissionPending { prepared: Option<Prepared>, manifest: Manifest, mount: SectionMountId,
        retry_after_100ns: u64, last_status: u32 },
    Rechecking { id: u64, prepared: Option<Prepared>, manifest: Manifest, mount: SectionMountId,
        started_ticks: u64, start_after_print: bool, trace: bool },
    Stalled(StalledState),
}
mod nt_config_client { pub(super) type PreparedSystemHiveCheckpoint = super::Prepared; }
mod nt_fs {
    pub(super) type WalSnapshotManifest = super::Manifest;
    pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
    pub const STATUS_DATA_ERROR: u32 = 0xc000_003e;
}
mod snapshot_storage {
    use super::*;
    pub(super) type Lease = super::Lease;
    pub const BUSY: u32 = 0x8000_0011;
    pub fn begin_wal_continuation_recheck_returning_lease(
        lease: Lease,
    ) -> Result<u64, (u32, Lease)> {
        Err((BEGIN_STATUS.load(Ordering::Acquire), lease))
    }
    pub fn begin_wal_continuation_recheck_with_lease(lease: Lease) -> Result<u64, u32> {
        Err(begin_wal_continuation_recheck_returning_lease(lease).unwrap_err().0)
    }
    pub fn recheck_was_aborted_no_effect(id: u64) -> bool {
        id == 7 && NO_EFFECT_ABORT.load(Ordering::Acquire)
    }
}
fn block(status: u32) -> u32 { status }
fn disk_census_ticks() -> u64 { 1 }
fn reserve_trace() -> bool { false }
fn trace_started(_: u64, _: Manifest, _: bool) {}
fn mark_runtime_dirty() {}
fn monotonic_time_100ns() -> u64 { 100_000_000 }
fn reset() {
    unsafe { WORK = None; }
    PREPARED_DROPS.store(0, Ordering::Release);
    LEASE_DROPS.store(0, Ordering::Release);
    BEGIN_STATUS.store(snapshot_storage::BUSY, Ordering::Release);
    NO_EFFECT_ABORT.store(true, Ordering::Release);
}
"#;

const CASES: &str = r#"
fn manifest() -> Manifest { Manifest { incarnation: 1, base_serial: 3,
    high_water_serial: 7, high_water_end_lba: 20 } }
#[test]
fn preentry_refusal_retains_cm_preparation_and_releases_only_the_unentered_lease() {
    reset();
    let status = unsafe { begin_recheck_with_prepared(Lease, Some(Prepared), manifest(), MOUNT) };
    assert_eq!(status, snapshot_storage::BUSY);
    assert_eq!(PREPARED_DROPS.load(Ordering::Acquire), 0);
    assert_eq!(LEASE_DROPS.load(Ordering::Acquire), 1);
    assert!(matches!(unsafe { &*core::ptr::addr_of!(WORK) },
        Some(Work::AdmissionPending { prepared: Some(_), mount: MOUNT, .. })));
}
#[test]
fn proven_no_effect_recheck_abort_keeps_preparation_for_timer_retry() {
    reset();
    unsafe { WORK = Some(Work::Rechecking { id: 7, prepared: Some(Prepared),
        manifest: manifest(), mount: MOUNT, started_ticks: 1,
        start_after_print: true, trace: false }); }
    assert_eq!(failed_recheck(0xc000_00a3), Err(snapshot_storage::BUSY));
    assert_eq!(PREPARED_DROPS.load(Ordering::Acquire), 0);
    assert!(matches!(unsafe { &*core::ptr::addr_of!(WORK) },
        Some(Work::AdmissionPending { prepared: Some(_), mount: MOUNT, .. })));
}
#[test]
fn contradictory_preentry_refusal_stalls_with_both_owners_retained() {
    reset();
    BEGIN_STATUS.store(nt_fs::STATUS_DATA_ERROR, Ordering::Release);
    let status = unsafe { begin_recheck_with_prepared(Lease, Some(Prepared), manifest(), MOUNT) };
    assert_eq!(status, nt_fs::STATUS_DATA_ERROR);
    assert_eq!(PREPARED_DROPS.load(Ordering::Acquire), 0);
    assert_eq!(LEASE_DROPS.load(Ordering::Acquire), 0);
    assert!(matches!(unsafe { &*core::ptr::addr_of!(WORK) },
        Some(Work::Stalled(StalledState::Admission { _prepared: Some(_),
            _lease: Some(_), _mount: MOUNT, .. }))));
}
#[test]
fn uncertain_recheck_error_cannot_release_the_cm_preparation() {
    reset();
    NO_EFFECT_ABORT.store(false, Ordering::Release);
    unsafe { WORK = Some(Work::Rechecking { id: 7, prepared: Some(Prepared),
        manifest: manifest(), mount: MOUNT, started_ticks: 1,
        start_after_print: true, trace: false }); }
    assert_eq!(failed_recheck(nt_fs::STATUS_DATA_ERROR), Err(nt_fs::STATUS_DATA_ERROR));
    assert_eq!(PREPARED_DROPS.load(Ordering::Acquire), 0);
    assert!(matches!(unsafe { &*core::ptr::addr_of!(WORK) },
        Some(Work::Rechecking { prepared: Some(_), mount: MOUNT, .. })));
}
#[test]
fn same_wal_serial_cannot_change_its_exact_end_lba() {
    let original = manifest();
    assert!(!manifest_contradiction(original, original));
    let mut changed = original;
    changed.high_water_end_lba += 1;
    assert!(manifest_contradiction(changed, original));
    changed.high_water_serial += 1;
    assert!(!manifest_contradiction(changed, original),
        "a verified later serial may extend the WAL while CM excludes new SYSTEM writes");
}
"#;
