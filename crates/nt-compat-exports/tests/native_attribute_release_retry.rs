//! The name-based attribute File stays owned when queueing CLEANUP/CLOSE is refused.

use std::process::Command;

#[test]
fn exact_temporary_file_release_retries_without_reusing_identity() {
    let source = include_str!("../../../components/ntos-executive/src/exec_attribute_query.rs");
    let start = source.find("struct ReleaseOwner {").expect("production release owner");
    let end = source[start..].find("\nimpl ExecNtHandler {").expect("end of release owner");
    let owner = &source[start..start + end];
    let fixture = [r#"
#![allow(static_mut_refs)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static REFUSE: AtomicBool = AtomicBool::new(false);
static RELEASES: AtomicU64 = AtomicU64::new(0);
mod alloc { pub mod vec { pub use std::vec::Vec; } }
mod driver_launch {
    pub fn abandon_unpublished_hosted_file(file: u64) -> Result<(), u32> {
        assert!(file == 41 || file == 42);
        if crate::REFUSE.load(std::sync::atomic::Ordering::SeqCst) { Err(0xc000_0056) }
        else {
            crate::RELEASES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
}
"#, owner, r#"
#[test]
fn refused_release_retains_exact_file_until_retry() {
    REFUSE.store(true, Ordering::SeqCst);
    let first = reserve_release_owner().unwrap();
    let second = reserve_release_owner().unwrap();
    release_or_retain(first, 41);
    assert_eq!(retry_attribute_releases(), 0);
    assert_eq!(RELEASES.load(Ordering::SeqCst), 0);
    REFUSE.store(false, Ordering::SeqCst);
    assert_eq!(retry_attribute_releases(), 1);
    assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
    release_or_retain(second, 42);
    assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
    assert_eq!(retry_attribute_releases(), 0);
}
"#].concat();
    let directory = std::env::temp_dir().join(format!(
        "nt-attribute-release-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "actual release owner must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "release owner regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
