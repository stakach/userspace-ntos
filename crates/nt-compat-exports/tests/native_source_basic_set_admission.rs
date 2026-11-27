//! Execute the native local SET entry with an owned Overlay File and observable metadata.
//! A FileBasic mutation must remain unentered until its delivery and preparation owners exist.

use std::process::Command;

#[test]
fn local_file_basic_waits_for_its_retained_owner_before_mutating() {
    let source = include_str!(
        "../../../components/ntos-executive/src/exec_file_set_information.rs"
    );
    let signature = "    pub(super) unsafe fn try_set_local_file_information(";
    let (_, tail) = source.split_once(signature).expect("native local SET entry");
    let (body, helper_tail) = tail
        .split_once("\n    /// Check both possible Basic row shapes")
        .expect("native Basic preflight boundary");
    let (helper, _) = helper_tail
        .split_once("\n    unsafe fn set_overlay_file_information(")
        .expect("native local SET entry boundary");
    let method = format!("{signature}{body}");
    let helper = format!("    /// Check both possible Basic row shapes{helper}");
    syn::parse_str::<syn::ImplItemFn>(method.trim())
        .expect("extract the complete production local SET method");
    syn::parse_str::<syn::ImplItemFn>(helper.trim())
        .expect("extract the complete production Basic preflight");

    let fixture = format!(
        "{MOCKS}\nmod native {{\nuse super::*;\nimpl ExecNtHandler {{\n{method}\n{helper}\n}}\n}}\n{CASES}"
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-native-basic-set-admission-{}", std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "native Basic fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(result.status.success(), "native Basic admission regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicUsize, Ordering};
static PREFLIGHTS: AtomicUsize = AtomicUsize::new(0);
static REFUSE_PREFLIGHT: AtomicUsize = AtomicUsize::new(0);
const STATUS_PENDING: u32 = 0x103;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
static mut PENDING_BASIC_PREPARED: BasicSidecar = BasicSidecar;
struct BasicSidecar;
impl BasicSidecar {
    fn cancel_admission(&mut self, _: u64) -> bool { true }
    fn admission_live(&self, _: &u64) -> bool { true }
}
static mut PENDING_FILE_IO: PendingFileTable = PendingFileTable;
struct PendingFileTable;
impl PendingFileTable {
    fn preflight_basic_primary(&self, _: &u64, row: nt_io_manager::PendingFileIo)
        -> Result<(), u32> {
        assert_eq!(row.reply_cap, 41);
        assert!(row.reply_required);
        PREFLIGHTS.fetch_add(1, Ordering::SeqCst);
        if REFUSE_PREFLIGHT.load(Ordering::SeqCst) != 0 { Err(1) } else { Ok(()) }
    }
}
mod inline_file_retirement {
    pub fn active_owner(_: u64) -> u64 { 19 }
}

mod nt_fs {
    pub const FILE_BASIC_INFORMATION: u32 = 4;
    pub const FILE_POSITION_INFORMATION: u32 = 14;
    pub const STATUS_SUCCESS: u32 = 0;
    pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc000_0004;
    pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
    pub const STATUS_DATA_ERROR: u32 = 0xc000_003e;
}

mod major { pub const IRP_MJ_SET_INFORMATION: u8 = 6; }

mod writable_fs {
    pub fn prepare_basic_owner(_: u64, input: [u8; 40])
        -> Result<super::nt_io_manager::PendingBasicPreparedOwner, u32> {
        Ok(super::nt_io_manager::PendingBasicPreparedOwner { input })
    }
    pub fn checkpoint_epochs() -> (u64, u64) { (0, 0) }
}

mod nt_process {
    pub struct Handle(pub u64);
    impl TryFrom<u64> for Handle {
        type Error = ();
        fn try_from(value: u64) -> Result<Self, Self::Error> { Ok(Self(value)) }
    }
    pub enum HandleObject { OverlayFile(u64), DiskFile { file: u64 } }
}

struct ProcessManager;
impl ProcessManager {
    fn lookup_handle(&self, _pid: u64, handle: nt_process::Handle)
        -> Option<nt_process::HandleObject> {
        Some(nt_process::HandleObject::OverlayFile(handle.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalFileObject { Overlay(u64), ReadonlyFile(u32) }
#[derive(Clone, Copy)]
struct LocalByteLockRoute { file_object: LocalFileObject, synchronous: bool }
struct BasicReplyReservation;
impl BasicReplyReservation { fn active(&self) -> u64 { 41 } }
struct ReadonlyFile { current_offset: u64 }
struct ReadonlyFileOpens { file: ReadonlyFile }
impl ReadonlyFileOpens {
    fn get_mut(&mut self, _id: u32) -> Option<&mut ReadonlyFile> { Some(&mut self.file) }
}

mod nt_io_manager {
    use super::{nt_fs, LocalFileObject};
    #[derive(Clone, Copy)]
    pub struct Status(pub u32);
    impl Status { pub fn raw(self) -> i32 { self.0 as i32 } }
    pub fn validate_set_information_value(class: u32, payload: &[u8])
        -> Result<(), Status> {
        if class == nt_fs::FILE_BASIC_INFORMATION && payload.len() == 40 {
            Ok(())
        } else {
            Err(Status(0xc000_000d))
        }
    }
    pub struct SetInformationCompletionPolicy;
    impl SetInformationCompletionPolicy {
        pub fn capture(_: u32, _: bool) -> Self { Self }
        pub fn resets_file_signal(&self) -> bool { true }
        pub fn publishes_iosb(&self, _: u32) -> bool { true }
        pub fn signals_file(&self, _: u32) -> bool { true }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingFileRoute { Local(LocalFileObject) }
    impl Default for PendingFileRoute {
        fn default() -> Self { Self::Local(LocalFileObject::Overlay(0)) }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingOwnedInline { pub status: u32, pub information: u64 }
    pub struct PendingBasicPreparedOwner { pub input: [u8; 40] }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingFileBusy(pub u64);
    impl PendingFileBusy { pub fn new(owner: u64) -> Self { Self(owner) } }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PendingOwnedBasicPreflight(pub u64);
    impl PendingOwnedBasicPreflight {
        pub fn new(required_epoch: u64) -> Self { Self(required_epoch) }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingFileIoOperation {
        Empty,
        OwnedInline(PendingOwnedInline),
        OwnedBasicPreflight(PendingOwnedBasicPreflight),
    }
    impl Default for PendingFileIoOperation {
        fn default() -> Self { Self::Empty }
    }
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PendingFileIo {
        pub route: PendingFileRoute,
        pub irp_id: u64,
        pub major: u8,
        pub operation: PendingFileIoOperation,
        pub pi: u32,
        pub tid: u64,
        pub badge: u64,
        pub busy: Option<PendingFileBusy>,
        pub iosb_va: u64,
        pub signal_file: bool,
        pub completion_port_suppressed: bool,
        pub event_obj_idx: u64,
        pub reply_cap: u64,
        pub reply_required: bool,
    }
    impl PendingFileIo {
        pub fn owned_terminal_result(&self) -> Option<(u32, u64)> {
            match self.operation {
                PendingFileIoOperation::OwnedInline(result) => {
                    Some((result.status, result.information))
                }
                _ => None,
            }
        }
    }
}
use nt_io_manager::PendingFileRoute;

struct ExecNtHandler {
    pm: ProcessManager,
    pi: usize,
    current_tid: u64,
    current_badge: u64,
    readonly_file_opens: ReadonlyFileOpens,
    pending_file_io_transfer: Option<nt_io_manager::PendingFileIo>,
    pending_basic_prepared_transfer: Option<nt_io_manager::PendingBasicPreparedOwner>,
    pending_basic_primary_reservation: Option<u64>,
    pending_basic_sidecar_reservation: Option<u64>,
    pending_basic_reply_reservation: Option<BasicReplyReservation>,
    current_synchronous_file: Option<u64>,
    pending_file_io_wait: bool,
    metadata_last_write: u64,
    metadata_effects: usize,
    file_references: usize,
}

impl ExecNtHandler {
    fn new() -> Self {
        Self {
            pm: ProcessManager, pi: 1, current_tid: 7, current_badge: 9,
            readonly_file_opens: ReadonlyFileOpens {
                file: ReadonlyFile { current_offset: 0 },
            },
            pending_file_io_transfer: None, pending_basic_prepared_transfer: None,
            pending_basic_primary_reservation: None,
            pending_basic_sidecar_reservation: None,
            pending_basic_reply_reservation: None,
            current_synchronous_file: Some(19),
            pending_file_io_wait: false,
            metadata_last_write: 0, metadata_effects: 0, file_references: 0,
        }
    }
    fn pm_pid_for_pi(&self, _: usize) -> Option<u64> { Some(1) }
    fn local_file_io_route_for(&self, handle: u64)
        -> Result<Option<LocalByteLockRoute>, u32> {
        Ok(Some(LocalByteLockRoute {
            file_object: LocalFileObject::Overlay(handle), synchronous: true,
        }))
    }
    fn reserve_local_file_io_delivery(&mut self) -> Result<u64, u32> { Ok(17) }
    fn reserve_local_basic_file_io_delivery(&mut self) -> Result<u64, u32> {
        self.pending_basic_primary_reservation = Some(17);
        self.pending_basic_sidecar_reservation = Some(18);
        self.pending_basic_reply_reservation = Some(BasicReplyReservation);
        Ok(17)
    }
    fn begin_local_file_io(&mut self, _: LocalFileObject) -> Result<(), u32> {
        assert_eq!(PREFLIGHTS.load(Ordering::SeqCst), 2,
            "Basic row/Reply checks must precede the File retain and signal reset");
        self.file_references += 1;
        Ok(())
    }
    fn retain_local_file_io_reference(&mut self, _: LocalFileObject) -> Result<(), u32> {
        self.file_references += 1;
        Ok(())
    }
    fn set_overlay_file_information(&mut self, _: u64, class: u32, payload: &[u8]) -> u32 {
        assert_eq!(class, nt_fs::FILE_BASIC_INFORMATION);
        self.metadata_last_write = u64::from_le_bytes(payload[16..24].try_into().unwrap());
        self.metadata_effects += 1;
        nt_fs::STATUS_SUCCESS
    }
}
"#;

const CASES: &str = r#"
#[test]
fn valid_file_basic_has_no_effect_before_its_delivery_owner_is_published() {
    PREFLIGHTS.store(0, Ordering::SeqCst);
    REFUSE_PREFLIGHT.store(0, Ordering::SeqCst);
    let mut handler = ExecNtHandler::new();
    let mut basic = [0u8; 40];
    basic[16..24].copy_from_slice(&777u64.to_le_bytes());
    let status = unsafe {
        handler.try_set_local_file_information(
            19, 0x2000, nt_fs::FILE_BASIC_INFORMATION, &basic,
        )
    };
    assert_eq!(status, Some(STATUS_PENDING));
    assert_eq!(handler.file_references, 1);
    assert_eq!(handler.metadata_effects, 0,
        "FileBasic must not mutate before the retained preparation and Reply are admitted");
    assert_eq!(handler.metadata_last_write, 0);
    let staged = handler.pending_file_io_transfer
        .expect("accepted Basic must stage a delivery owner");
    assert_eq!(staged.irp_id, 17);
    assert_eq!(staged.iosb_va, 0x2000);
    assert_eq!(staged.owned_terminal_result(), None,
        "Basic cannot be terminal before its owned preflight runs");
    assert_eq!(handler.pending_basic_prepared_transfer.as_ref().unwrap().input, basic);
    assert_eq!(handler.pending_basic_primary_reservation, Some(17));
    assert_eq!(handler.pending_basic_sidecar_reservation, Some(18));
    assert_eq!(PREFLIGHTS.load(Ordering::SeqCst), 2);
    assert!(handler.pending_file_io_wait);
}
#[test]
fn refused_basic_preflight_does_not_retain_or_reset_the_file() {
    PREFLIGHTS.store(0, Ordering::SeqCst);
    REFUSE_PREFLIGHT.store(1, Ordering::SeqCst);
    let mut handler = ExecNtHandler::new();
    let basic = [0u8; 40];
    let status = unsafe {
        handler.try_set_local_file_information(
            19, 0x2000, nt_fs::FILE_BASIC_INFORMATION, &basic,
        )
    };
    assert_eq!(status, Some(nt_fs::STATUS_DATA_ERROR));
    assert_eq!(handler.file_references, 0);
    assert_eq!(handler.metadata_effects, 0);
    assert!(handler.pending_file_io_transfer.is_none());
    REFUSE_PREFLIGHT.store(0, Ordering::SeqCst);
}
"#;
