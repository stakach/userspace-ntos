//! A restored SYSTEM WAL suffix can need a fold after CM mounts the replayed hive clean (#8).
//! Execute both production fold admissions with an explicitly valid cached fence so a clean-CM
//! refusal cannot be mistaken for a corrupt paired snapshot.

use std::process::Command;

#[test]
fn restored_system_wal_can_fold_a_clean_composed_cm_generation() {
    let boot = include_str!(
        "../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs"
    );
    let native = include_str!(
        "../../../components/ntos-executive/src/writable_fs/system_wal_fold/native.rs"
    );
    run_admission(boot,
        "    let manifest = snapshot_storage::peek_wal_continuation(&mut lease)",
        "    let old = snapshot_storage::take_wal_continuation(&mut lease);",
        "boot");
    run_admission(native,
        "    let manifest = snapshot_storage::cached_wal_manifest(&lease)",
        "    let id = snapshot_storage::begin_wal_continuation_recheck_with_lease(lease)?;",
        "native");
}

fn run_admission(source: &str, start: &str, end: &str, label: &str) {
    let (_, tail) = source.split_once(start).expect("production fold admission");
    let (tail, _) = tail.split_once(end).expect("production continuation transfer");
    let admission = format!("{start}{tail}");
    let fixture = format!(
        "{MOCKS}\nfn admit() -> Result<bool, u32> {{\n    let mut lease = Lease;\n\
         {admission}\n    Ok(true)\n}}\n{CASES}"
    );
    let dir = std::env::temp_dir().join(format!(
        "nt-restored-system-wal-fold-{label}-{}", std::process::id()
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
    assert!(
        compiled.status.success(),
        "production fold admission fixture failed to compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        result.status.success(),
        "restored SYSTEM WAL fold regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicBool, Ordering};
static SYSTEM_WAL_FOLD_REQUIRED: AtomicBool = AtomicBool::new(false);
static WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED: AtomicBool = AtomicBool::new(false);
static CACHED_FENCE_VALID: AtomicBool = AtomicBool::new(true);
static CM_HAS_NEW_DIRTY_SEQUENCE: AtomicBool = AtomicBool::new(false);
struct Lease;
struct Manifest { base_serial: u64, high_water_serial: u64 }
mod nt_fs { pub const STATUS_DATA_ERROR: u32 = 0xc000_003e; }
mod snapshot_storage {
    use super::*;
    fn manifest() -> Result<Manifest, u32> {
        if !CACHED_FENCE_VALID.load(Ordering::Acquire) {
            return Err(nt_fs::STATUS_DATA_ERROR);
        }
        Ok(Manifest { base_serial: 8, high_water_serial: 265 })
    }
    pub fn peek_wal_continuation(_: &mut Lease) -> Result<Manifest, u32> { manifest() }
    pub fn cached_wal_manifest(_: &Lease) -> Result<Manifest, u32> { manifest() }
}
fn config_manager_prepare_system_hive_checkpoint() -> Result<Option<()>, i32> {
    Ok(CM_HAS_NEW_DIRTY_SEQUENCE.load(Ordering::Acquire).then_some(()))
}
fn config_manager_prepare_system_hive_checkpoint_for_restored_wal() -> Result<(), i32> {
    Ok(())
}
fn block(status: u32) -> u32 {
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    status
}
fn report_fold_failure(_: &[u8], status: u32) -> u32 { status }
fn reset(system_suffix: bool, fence_valid: bool, cm_dirty: bool) {
    SYSTEM_WAL_FOLD_REQUIRED.store(system_suffix, Ordering::Release);
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(false, Ordering::Release);
    CACHED_FENCE_VALID.store(fence_valid, Ordering::Release);
    CM_HAS_NEW_DIRTY_SEQUENCE.store(cm_dirty, Ordering::Release);
}
"#;

const CASES: &str = r#"
#[test]
fn valid_replayed_system_suffix_with_clean_cm_can_enter_fold() {
    reset(true, true, false);
    assert_eq!(admit(), Ok(true),
        "a verified SYSTEM suffix needs the exact composed CM generation, even without new CM dirt");
    assert!(!WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire));
}
#[test]
fn bad_cached_fence_is_a_distinct_data_error() {
    reset(true, false, false);
    assert_eq!(admit(), Err(nt_fs::STATUS_DATA_ERROR));
    assert!(WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire));
}
#[test]
fn non_system_wal_with_clean_cm_does_not_require_a_system_checkpoint() {
    reset(false, true, false);
    assert_eq!(admit(), Ok(true));
}
#[test]
fn newly_dirty_cm_already_supplies_a_prepared_image() {
    reset(true, true, true);
    assert_eq!(admit(), Ok(true));
}
"#;
