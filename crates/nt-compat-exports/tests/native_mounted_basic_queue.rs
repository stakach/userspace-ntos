//! Exercise the native mounted Basic queue with a controlled File, mount and snapshot producer.
//! The fixture compiles the production queue module, so these assertions cover its transitions.

use std::process::Command;

#[test]
fn mounted_basic_queue_retains_exact_owner_through_completion_ack() {
    let source = include_str!(
        "../../../components/ntos-executive/src/mounted_basic_set.rs"
    );
    syn::parse_file(source).expect("production mounted Basic queue parses");
    let fixture = format!("{MOCKS}\nmod native {{\n{source}\n{CASES}\n}}\n");
    let directory = std::env::temp_dir().join(format!(
        "nt-mounted-basic-queue-{}", std::process::id()
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
    assert!(compiled.status.success(), "mounted Basic queue fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(result.status.success(), "mounted Basic queue regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NtStatus(i32);
impl NtStatus {
    const INVALID_PARAMETER: Self = Self(0xc000_000du32 as i32);
    const INVALID_HANDLE: Self = Self(0xc000_0008u32 as i32);
    const DEVICE_NOT_READY: Self = Self(0xc000_00a3u32 as i32);
    const INSUFFICIENT_RESOURCES: Self = Self(0xc000_009au32 as i32);
    const NOT_SUPPORTED: Self = Self(0xc000_00bbu32 as i32);
    const CANCELLED: Self = Self(0xc000_0120u32 as i32);
    const SUCCESS: Self = Self(0);
}
const RESIDENT_BUSY: NtStatus = NtStatus(0x8000_0011u32 as i32);
fn status(raw: u32) -> NtStatus { NtStatus(raw as i32) }
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}

static PHYSICAL_MOUNT: AtomicU64 = AtomicU64::new(3);
static OVERLAY_MOUNT: AtomicU64 = AtomicU64::new(4);
static OPEN_OVERLAY_FILE: AtomicU64 = AtomicU64::new(55);
// 0 Boot, 1 Native, 2 Draining, 3 absent.
static ROUTE: AtomicUsize = AtomicUsize::new(1);
static RESIDENT: AtomicUsize = AtomicUsize::new(1);
static PREPARE_BUSY: AtomicUsize = AtomicUsize::new(0);
static APPLY_BUSY: AtomicUsize = AtomicUsize::new(0);
static PREPARES: AtomicUsize = AtomicUsize::new(0);
static APPLIES: AtomicUsize = AtomicUsize::new(0);

mod nt_memory_manager {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SectionMountId(pub u64);
    impl SectionMountId { pub fn value(self) -> u64 { self.0 } }
}
mod nt_fs {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LayeredOpenContextId(pub u64);
    impl LayeredOpenContextId { pub fn raw(self) -> u64 { self.0 } }
    #[derive(Clone, Copy)]
    pub enum LayeredOpenSource { Overlay { file_id: u64 }, Installed }
    #[derive(Clone, Copy)]
    pub enum BlockSourceKind { Boot, Native, Draining }
}
mod nt_io_manager {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IrpId(pub u64);
    impl IrpId { pub fn raw(self) -> u64 { self.0 } }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FileId(pub u64);
    impl FileId { pub fn raw(self) -> u64 { self.0 } }
    pub struct IrpProjection { pub irp_id: IrpId, pub file_id: Option<FileId> }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DispatchOutcome { Pending }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DriverCompletion {
        pub irp_id: IrpId, pub status: super::NtStatus,
        pub information: u64, pub file_context: Option<u64>,
    }
    pub struct PendingBasicPreparedOwner<FileReference> {
        file: FileReference,
        applied: bool,
    }
    impl<FileReference> PendingBasicPreparedOwner<FileReference> {
        pub fn new(file: FileReference) -> Self { Self { file, applied: false } }
        pub fn stable_file_id(&self) -> u64 { 55 }
        pub fn into_file(self) -> FileReference { self.file }
        pub fn mark_applied(&mut self) -> bool {
            if self.applied { false } else { self.applied = true; true }
        }
    }
}
use nt_io_manager::{DispatchOutcome, DriverCompletion, IrpId, IrpProjection};

mod fs_loader {
    use super::*;
    pub unsafe fn exec_fs_mount_identity() -> Option<nt_memory_manager::SectionMountId> {
        Some(nt_memory_manager::SectionMountId(PHYSICAL_MOUNT.load(Ordering::SeqCst)))
    }
    pub fn exec_block_route_kind(_: nt_memory_manager::SectionMountId)
        -> Option<nt_fs::BlockSourceKind> {
        match ROUTE.load(Ordering::SeqCst) {
            0 => Some(nt_fs::BlockSourceKind::Boot),
            1 => Some(nt_fs::BlockSourceKind::Native),
            2 => Some(nt_fs::BlockSourceKind::Draining),
            _ => None,
        }
    }
}
mod writable_fs {
    use super::*;
    pub unsafe fn mounted_basic_namespace_identity()
        -> Option<nt_memory_manager::SectionMountId> {
        Some(nt_memory_manager::SectionMountId(OVERLAY_MOUNT.load(Ordering::SeqCst)))
    }
    pub unsafe fn prepared_overlay_resident() -> Result<bool, u32> {
        Ok(RESIDENT.load(Ordering::SeqCst) != 0)
    }
    pub unsafe fn prepare_basic_with_reference<FileReference>(
        _: u64, _: [u8; 40], file: FileReference,
    ) -> Result<nt_io_manager::PendingBasicPreparedOwner<FileReference>, (u32, FileReference)> {
        if PREPARE_BUSY.load(Ordering::SeqCst) != 0 {
            return Err((RESIDENT_BUSY.0 as u32, file));
        }
        PREPARES.fetch_add(1, Ordering::SeqCst);
        Ok(nt_io_manager::PendingBasicPreparedOwner::new(file))
    }
    pub unsafe fn apply_mounted_basic_snapshot_once<FileReference>(
        owner: &mut nt_io_manager::PendingBasicPreparedOwner<FileReference>,
    ) -> Result<u32, u32> {
        if APPLY_BUSY.load(Ordering::SeqCst) != 0 {
            return Err(RESIDENT_BUSY.0 as u32);
        }
        if owner.mark_applied() {
            APPLIES.fetch_add(1, Ordering::SeqCst);
        }
        Ok(NtStatus::SUCCESS.0 as u32)
    }
}

#[derive(Clone, Copy)]
struct OpenRecord { source: nt_fs::LayeredOpenSource }
struct Opens;
impl Opens {
    fn get(&self, context: nt_fs::LayeredOpenContextId, file: u64)
        -> Result<OpenRecord, u32> {
        if context.raw() == 77 && file == 41 {
            Ok(OpenRecord { source: nt_fs::LayeredOpenSource::Overlay {
                file_id: OPEN_OVERLAY_FILE.load(Ordering::SeqCst),
            } })
        } else {
            Err(NtStatus::INVALID_HANDLE.0 as u32)
        }
    }
}
#[derive(Clone, Copy)]
struct MountedBinding {
    context: nt_fs::LayeredOpenContextId,
    overlay_open: bool,
    overlay_body: bool,
}
struct MountedVolumeBackend {
    opens: Opens,
    bindings: Vec<Option<MountedBinding>>,
    pending_basic: Vec<native::MountedBasicSet>,
}
fn context_index(context: nt_fs::LayeredOpenContextId) -> Option<usize> {
    usize::try_from(context.raw().checked_sub(1)?).ok()
}
"#;

const CASES: &str = r#"
fn reset() {
    PHYSICAL_MOUNT.store(3, Ordering::SeqCst);
    OVERLAY_MOUNT.store(4, Ordering::SeqCst);
    OPEN_OVERLAY_FILE.store(55, Ordering::SeqCst);
    ROUTE.store(1, Ordering::SeqCst);
    RESIDENT.store(1, Ordering::SeqCst);
    PREPARE_BUSY.store(0, Ordering::SeqCst);
    APPLY_BUSY.store(0, Ordering::SeqCst);
    PREPARES.store(0, Ordering::SeqCst);
    APPLIES.store(0, Ordering::SeqCst);
}

fn backend() -> MountedVolumeBackend {
    let mut bindings = vec![None; 77];
    bindings[76] = Some(MountedBinding {
        context: nt_fs::LayeredOpenContextId(77),
        overlay_open: true,
        overlay_body: false,
    });
    MountedVolumeBackend { opens: Opens, bindings, pending_basic: Vec::new() }
}

fn input(attrs: u32) -> [u8; 40] {
    let mut input = [0; 40];
    input[32..36].copy_from_slice(&attrs.to_le_bytes());
    input
}

fn park(backend: &mut MountedVolumeBackend, irp: u64, value: &[u8])
    -> Result<DispatchOutcome, NtStatus> {
    backend.park_basic(
        &IrpProjection { irp_id: IrpId(irp), file_id: Some(nt_io_manager::FileId(41)) },
        nt_fs::LayeredOpenContextId(77), 55, value,
    )
}

#[test]
fn copied_input_and_exact_irp_are_owned_before_any_effect() {
    reset();
    let mut backend = backend();
    let mut bytes = input(16);
    assert_eq!(park(&mut backend, 101, &bytes), Ok(DispatchOutcome::Pending));
    bytes.fill(0);
    assert_eq!(backend.pending_basic[0].input, input(16));
    assert_eq!(backend.pending_basic[0].identity.irp, IrpId(101));
    assert_eq!(backend.pending_basic[0].identity.file, nt_io_manager::FileId(41));
    assert_eq!(backend.pending_basic[0].identity.context,
               nt_fs::LayeredOpenContextId(77));
    assert_eq!(backend.pending_basic[0].identity.mount,
               nt_memory_manager::SectionMountId(3));
    assert_eq!(backend.pending_basic[0].identity.overlay_mount,
               nt_memory_manager::SectionMountId(4));
    assert_eq!(backend.pending_basic[0].identity.overlay_file, 55);
    assert_eq!(park(&mut backend, 101, &input(17)), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(PREPARES.load(Ordering::SeqCst), 0);
    assert_eq!(APPLIES.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_body_and_busy_gates_preserve_one_prepared_owner_until_ack() {
    reset();
    let mut backend = backend();
    assert_eq!(park(&mut backend, 101, &input(16)), Ok(DispatchOutcome::Pending));
    // CLEANUP has closed the handle while the canonical File still owns its I/O body.
    let binding = backend.bindings[76].as_mut().unwrap();
    binding.overlay_open = false;
    binding.overlay_body = true;
    ROUTE.store(2, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 0);
    ROUTE.store(1, Ordering::SeqCst);
    RESIDENT.store(0, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 0);
    RESIDENT.store(1, Ordering::SeqCst);
    PREPARE_BUSY.store(1, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 0);
    assert_eq!(PREPARES.load(Ordering::SeqCst), 0);
    PREPARE_BUSY.store(0, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(PREPARES.load(Ordering::SeqCst), 1);
    APPLY_BUSY.store(1, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 0);
    APPLY_BUSY.store(0, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(APPLIES.load(Ordering::SeqCst), 1);
    assert_eq!(backend.service_basic(), 0);
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::SUCCESS);
    assert!(backend.poll_basic_completion().is_none());
    assert_eq!(backend.pending_basic.len(), 1);
    assert_eq!(backend.ack_basic_completion(IrpId(102)), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(backend.pending_basic.len(), 1);
    assert_eq!(backend.ack_basic_completion(IrpId(101)), Ok(()));
    assert!(backend.pending_basic.is_empty());
    assert_eq!(PREPARES.load(Ordering::SeqCst), 1);
    assert_eq!(APPLIES.load(Ordering::SeqCst), 1);
}

#[test]
fn stale_mount_or_context_terminalizes_without_preparing_or_mutating() {
    reset();
    let mut backend = backend();
    assert_eq!(park(&mut backend, 101, &input(16)), Ok(DispatchOutcome::Pending));
    OVERLAY_MOUNT.store(5, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::DEVICE_NOT_READY);
    assert_eq!(backend.ack_basic_completion(IrpId(101)), Ok(()));
    OVERLAY_MOUNT.store(4, Ordering::SeqCst);
    assert_eq!(park(&mut backend, 102, &input(17)), Ok(DispatchOutcome::Pending));
    backend.bindings[76].as_mut().unwrap().context = nt_fs::LayeredOpenContextId(88);
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::INVALID_HANDLE);
    assert_eq!(backend.ack_basic_completion(IrpId(102)), Ok(()));
    backend.bindings[76].as_mut().unwrap().context = nt_fs::LayeredOpenContextId(77);
    assert_eq!(park(&mut backend, 103, &input(17)), Ok(DispatchOutcome::Pending));
    OPEN_OVERLAY_FILE.store(56, Ordering::SeqCst);
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::INVALID_HANDLE);
    assert_eq!(backend.ack_basic_completion(IrpId(103)), Ok(()));
    assert_eq!(PREPARES.load(Ordering::SeqCst), 0);
    assert_eq!(APPLIES.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_before_effect_publishes_one_terminal_and_waits_for_ack() {
    reset();
    let mut backend = backend();
    assert_eq!(park(&mut backend, 101, &input(16)), Ok(DispatchOutcome::Pending));
    assert_eq!(backend.cancel_basic(IrpId(102)), Err(NtStatus::NOT_SUPPORTED));
    assert_eq!(backend.cancel_basic(IrpId(101)), Ok(()));
    assert_eq!(backend.service_basic(), 0);
    assert_eq!(backend.ack_basic_completion(IrpId(101)), Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::CANCELLED);
    assert!(backend.poll_basic_completion().is_none());
    assert_eq!(backend.cancel_basic(IrpId(101)), Err(NtStatus::NOT_SUPPORTED));
    assert_eq!(backend.ack_basic_completion(IrpId(101)), Ok(()));
    assert_eq!(PREPARES.load(Ordering::SeqCst), 0);
    assert_eq!(APPLIES.load(Ordering::SeqCst), 0);
    assert_eq!(park(&mut backend, 102, &input(17)), Ok(DispatchOutcome::Pending));
    assert_eq!(backend.service_basic(), 1);
    assert_eq!(PREPARES.load(Ordering::SeqCst), 1);
    assert_eq!(backend.cancel_basic(IrpId(102)), Ok(()));
    assert_eq!(backend.service_basic(), 0);
    assert_eq!(backend.poll_basic_completion().unwrap().status, NtStatus::CANCELLED);
    assert_eq!(backend.ack_basic_completion(IrpId(102)), Ok(()));
    assert_eq!(APPLIES.load(Ordering::SeqCst), 0);
}
"#;
