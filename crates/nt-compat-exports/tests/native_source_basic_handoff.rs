//! Compile the native Basic handoff against owned Reply/File/sidecar mocks.

use std::process::Command;

#[test]
fn native_basic_handoff_uses_one_pre_reserved_file_row() {
    let source = include_str!(
        "../../../components/ntos-executive/src/native_basic_set_handoff.rs"
    );
    let signature = "pub(super) unsafe fn publish_basic_preflighted(";
    let (_, tail) = source.split_once(signature).expect("native Basic handoff function");
    let method = format!("{signature}{tail}");
    syn::parse_str::<syn::ItemFn>(&method).expect("extract complete native Basic handoff");
    let fixture = format!("{MOCKS}\nmod native {{\nuse super::*;\n{method}\n}}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-basic-handoff-{}", std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native Basic handoff fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(result.status.success(), "native Basic handoff regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicUsize, Ordering};
static TRANSFERRED_FILE: AtomicUsize = AtomicUsize::new(0);
static PUBLISHED_CALLER: AtomicUsize = AtomicUsize::new(0);
static CANCELLED_SIDECAR: AtomicUsize = AtomicUsize::new(0);
static mut PENDING_BASIC_PREPARED: nt_io_manager::PendingBasicPreparedTable =
    nt_io_manager::PendingBasicPreparedTable::new();
mod nt_fs {
    pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
    pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
    pub const STATUS_DATA_ERROR: u32 = 0xc000_003e;
}
mod writable_fs {
    pub struct BasicFileReference;
    impl BasicFileReference {
        pub fn into_row(self) {
            super::TRANSFERRED_FILE.fetch_add(1, super::Ordering::SeqCst);
        }
    }
}
mod nt_io_manager {
    use super::writable_fs::BasicFileReference;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingFileIoIdentity(pub usize);
    impl PendingFileIoIdentity { pub fn slot(self) -> usize { self.0 } }
    pub struct PendingBasicPrimaryReservation(pub usize);
    impl PendingBasicPrimaryReservation {
        pub fn identity(&self) -> PendingFileIoIdentity { PendingFileIoIdentity(self.0) }
    }
    pub struct PendingBasicPreparedReservation;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingFileIoParkError {
        StaleReservation, OccupiedReservation, InvalidRecord, DuplicateIrp,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingBasicPreparedAdmissionError {
        SidecarUnavailable, PendingRow(PendingFileIoParkError),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingOwnedInline { pub status: u32, pub information: u64 }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingFileIoOperation { Basic, OwnedInline(PendingOwnedInline) }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingFileIo {
        pub irp_id: u64,
        pub operation: PendingFileIoOperation,
        pub iosb_va: u64,
        pub signal_file: bool,
        pub reply_cap: u64,
    }
    pub struct PendingBasicPreparedOwner<FileReference> { file: FileReference }
    impl<FileReference> PendingBasicPreparedOwner<FileReference> {
        pub fn new(file: FileReference) -> Self { Self { file } }
        pub fn into_file(self) -> FileReference { self.file }
    }
    pub struct PendingFileIoTable { pub primary: Option<PendingFileIo> }
    impl PendingFileIoTable {
        pub fn new() -> Self { Self { primary: None } }
        pub fn try_park_basic_primary(&mut self, primary: PendingBasicPrimaryReservation,
            row: PendingFileIo) -> Result<PendingFileIoIdentity,
                (PendingFileIoParkError, PendingFileIo, PendingBasicPrimaryReservation)> {
            self.primary = Some(row);
            Ok(primary.identity())
        }
    }
    pub struct PendingBasicPreparedTable { pub refusal: bool }
    impl PendingBasicPreparedTable {
        pub const fn new() -> Self { Self { refusal: false } }
        pub fn cancel_admission(&mut self, _: PendingBasicPreparedReservation) -> bool {
            super::CANCELLED_SIDECAR.fetch_add(1, super::Ordering::SeqCst);
            true
        }
        pub fn try_admit_pre_reserved_exact(&mut self, table: &mut PendingFileIoTable,
            sidecar: PendingBasicPreparedReservation, primary: PendingBasicPrimaryReservation,
            row: PendingFileIo, owner: PendingBasicPreparedOwner<BasicFileReference>,
        ) -> Result<PendingFileIoIdentity,
            (PendingBasicPreparedAdmissionError, PendingFileIo,
                PendingBasicPreparedOwner<BasicFileReference>, PendingBasicPrimaryReservation,
                PendingBasicPreparedReservation)> {
            if self.refusal {
                return Err((PendingBasicPreparedAdmissionError::SidecarUnavailable,
                    row, owner, primary, sidecar));
            }
            table.try_park_basic_primary(primary, row).map_err(|(error, row, primary)|
                (PendingBasicPreparedAdmissionError::PendingRow(error), row, owner,
                    primary, sidecar))
        }
    }
}
mod pending_file_caller {
    use super::*;
    pub unsafe fn publish_identity(_: nt_io_manager::PendingFileIoIdentity,
        _: nt_io_manager::PendingFileIo) {
        PUBLISHED_CALLER.fetch_add(1, Ordering::SeqCst);
    }
}
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn reset(refusal: bool) {
    TRANSFERRED_FILE.store(0, Ordering::SeqCst);
    PUBLISHED_CALLER.store(0, Ordering::SeqCst);
    CANCELLED_SIDECAR.store(0, Ordering::SeqCst);
    unsafe { (*std::ptr::addr_of_mut!(PENDING_BASIC_PREPARED)).refusal = refusal; }
}
fn row() -> nt_io_manager::PendingFileIo {
    nt_io_manager::PendingFileIo {
        irp_id: 101, operation: nt_io_manager::PendingFileIoOperation::Basic,
        iosb_va: 0x2000, signal_file: true, reply_cap: 41,
    }
}
"#;

const CASES: &str = r#"
#[test]
fn accepted_basic_publishes_the_primary_and_retains_one_file_owner() {
    reset(false);
    let mut table = nt_io_manager::PendingFileIoTable::new();
    let result = unsafe { native::publish_basic_preflighted(&mut table,
        nt_io_manager::PendingBasicPrimaryReservation(1),
        nt_io_manager::PendingBasicPreparedReservation, row(),
        nt_io_manager::PendingBasicPreparedOwner::new(writable_fs::BasicFileReference)) };
    assert_eq!(result.slot(), 1);
    assert_eq!(table.primary.unwrap().reply_cap, 41);
    assert_eq!(PUBLISHED_CALLER.load(Ordering::SeqCst), 1);
    assert_eq!(CANCELLED_SIDECAR.load(Ordering::SeqCst), 0);
    assert_eq!(TRANSFERRED_FILE.load(Ordering::SeqCst), 0);
}
"#;
