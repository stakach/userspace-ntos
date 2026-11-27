//! Execute the mounted provider's production SET admission with an exact writable File.
//! Basic metadata must have a pending owner before any in-memory mutation can run.

use std::process::Command;

#[test]
fn mounted_file_basic_is_retained_before_any_metadata_effect() {
    let source = include_str!(
        "../../../components/ntos-executive/src/mounted_set_information.rs"
    );
    let signature = "    fn set_file_information(";
    let (_, tail) = source.split_once(signature).expect("mounted SET method");
    let (body, _) = tail.split_once("\n    }\n}").expect("mounted SET method boundary");
    let method = format!("{signature}{body}\n    }}");
    syn::parse_str::<syn::ImplItemFn>(method.trim()).expect("production SET method parses");
    let owner_source = include_str!(
        "../../../components/ntos-executive/src/mounted_basic_set.rs"
    );
    let owner_signature = "    fn basic_owner_status(";
    let (_, owner_tail) = owner_source.split_once(owner_signature)
        .expect("mounted Basic owner status method");
    let (owner_body, _) = owner_tail.split_once("\n    }\n\n    pub(super) fn service_basic")
        .expect("mounted Basic owner status boundary");
    let owner_method = format!("{owner_signature}{owner_body}\n    }}");
    syn::parse_str::<syn::ImplItemFn>(owner_method.trim())
        .expect("production Basic owner status method parses");

    let fixture = format!("{MOCKS}\nmod native {{\nuse super::*;\nimpl MountedVolumeBackend {{\n{method}\n{owner_method}\n{PARK}\n}}\n{CASES}\n}}");
    let directory = std::env::temp_dir().join(format!(
        "nt-mounted-basic-admission-{}", std::process::id()
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
    assert!(compiled.status.success(), "mounted Basic fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(result.status.success(), "mounted Basic admission RED:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicUsize, Ordering};
static MUTATIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NtStatus(u32);
impl NtStatus {
    const ACCESS_DENIED: Self = Self(0xc000_0022);
    const INVALID_HANDLE: Self = Self(0xc000_0008);
    const INVALID_PARAMETER: Self = Self(0xc000_000d);
    const DEVICE_NOT_READY: Self = Self(0xc000_00a3);
    const SUCCESS: Self = Self(0);
}
fn status(raw: u32) -> NtStatus { NtStatus(raw) }
const RESIDENT_BUSY: NtStatus = NtStatus(0x8000_0011);

mod nt_memory_manager {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SectionMountId(pub u64);
}
static ROUTE: AtomicUsize = AtomicUsize::new(0);
mod fs_loader {
    use super::{nt_fs::BlockSourceKind, nt_memory_manager::SectionMountId, Ordering, ROUTE};
    pub unsafe fn exec_fs_mount_identity() -> Option<SectionMountId> {
        Some(SectionMountId(3))
    }
    pub fn exec_block_route_kind(_: SectionMountId) -> Option<BlockSourceKind> {
        Some(match ROUTE.load(Ordering::SeqCst) {
            0 => BlockSourceKind::Boot,
            1 => BlockSourceKind::Native,
            _ => BlockSourceKind::Draining,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchOutcome {
    Pending,
    Failed { status: NtStatus },
    Completed { status: NtStatus, information: u64, file_context: Option<u64> },
}
struct DispatchContext<'a> { system_buffer: &'a [u8] }

mod nt_types {
    #[derive(Clone, Copy)]
    pub struct AccessMask(pub u32);
    impl AccessMask { pub fn from_bits_retain(bits: u32) -> Self { Self(bits) } }
}
mod nt_io_manager {
    use super::nt_types::AccessMask;
    #[derive(Clone, Copy)]
    pub struct FileId(pub u64);
    impl FileId { pub fn raw(self) -> u64 { self.0 } }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum SetInformationControl { None }
    #[derive(Clone, Copy)]
    pub struct SetInformationParameters {
        pub info_class: u32, pub length: u32,
        pub target_file: Option<FileId>, pub control: SetInformationControl,
    }
    pub struct Contract;
    impl Contract {
        pub fn access_granted(self, access: AccessMask) -> bool {
            access.0 & 0x100 == 0x100
        }
    }
    pub fn set_information_contract(_: u32) -> Option<Contract> { Some(Contract) }
}
use nt_io_manager::{FileId, SetInformationControl, SetInformationParameters};
#[derive(Clone, Copy)]
enum IoParameters { SetInformation(SetInformationParameters) }
struct IrpProjection { irp_id: u64, file_id: Option<FileId>, parameters: IoParameters }

mod nt_fs {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LayeredOpenContextId(pub u64);
    impl LayeredOpenContextId { pub fn raw(self) -> u64 { self.0 } }
    #[derive(Clone, Copy)]
    pub enum LayeredOpenSource { Volume, Installed { file_id: u64 }, Overlay { file_id: u64 } }
    #[derive(Clone, Copy)]
    pub enum LayeredFileBacking { Volume, Installed, Writable }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BlockSourceKind { Boot, Native, Draining }
    pub struct LayeredSetInformation {
        pub class: u32, pub backing: LayeredFileBacking,
        pub is_directory: bool, pub shadows_installed: bool,
    }
    pub enum LayeredSetInformationAction {
        Writable, InstalledPosition(u64), Unchanged,
    }
    pub const FILE_BASIC_INFORMATION: u32 = 4;
    pub fn layered_set_information_decision(
        request: LayeredSetInformation, payload: &[u8],
    ) -> Result<LayeredSetInformationAction, u32> {
        assert_eq!(request.class, FILE_BASIC_INFORMATION);
        assert_eq!(payload.len(), 40);
        assert!(matches!(request.backing, LayeredFileBacking::Writable));
        Ok(LayeredSetInformationAction::Writable)
    }
}
mod writable_fs {
    pub unsafe fn mounted_basic_namespace_identity()
        -> Option<super::nt_memory_manager::SectionMountId> {
        Some(super::nt_memory_manager::SectionMountId(4))
    }
    pub unsafe fn set_information(_: u64, _: u32, _: &[u8]) -> u32 {
        super::MUTATIONS.fetch_add(1, super::Ordering::SeqCst);
        0
    }
}

#[derive(Clone, Copy)]
struct MountedBinding {
    granted_access: u32, is_directory: bool, shadows_installed: bool,
    overlay_open: bool, installed_open: Option<u32>,
    overlay_body: bool, context: nt_fs::LayeredOpenContextId,
}
#[derive(Clone, Copy)]
struct OpenRecord { source: nt_fs::LayeredOpenSource }
struct Opens;
impl Opens {
    fn get(&self, context: nt_fs::LayeredOpenContextId, file: u64)
        -> Result<OpenRecord, u32> {
        assert_eq!(context.0, 77);
        assert_eq!(file, 41);
        Ok(OpenRecord { source: nt_fs::LayeredOpenSource::Overlay { file_id: 55 } })
    }
}
struct InstalledOpen { current_offset: u64 }
struct Shares { open: InstalledOpen }
impl Shares {
    fn get_mut(&mut self, _: u32) -> Result<&mut InstalledOpen, u32> {
        Ok(&mut self.open)
    }
}
struct MountedVolumeBackend {
    opens: Opens, shares: Shares, bindings: Vec<Option<MountedBinding>>,
    mount: u64,
    captured: Option<(u64, u64, u64, u64, u64, [u8; 40])>,
}
#[derive(Clone, Copy)]
struct BasicIdentity {
    file: FileId, context: nt_fs::LayeredOpenContextId,
    mount: nt_memory_manager::SectionMountId,
    overlay_mount: nt_memory_manager::SectionMountId,
    overlay_file: u64,
}
fn context_index(context: nt_fs::LayeredOpenContextId) -> Option<usize> {
    usize::try_from(context.raw().checked_sub(1)?).ok()
}
"#;

const PARK: &str = r#"
    fn park_basic(&mut self, irp: &IrpProjection,
        context: nt_fs::LayeredOpenContextId, overlay_file: u64,
        payload: &[u8]) -> Result<DispatchOutcome, NtStatus> {
        let input: [u8; 40] = payload.try_into().map_err(|_| NtStatus::INVALID_PARAMETER)?;
        self.captured = Some((irp.irp_id, irp.file_id.unwrap().raw(), context.0,
            self.mount, overlay_file, input));
        Ok(DispatchOutcome::Pending)
    }
"#;

const CASES: &str = r#"
#[test]
fn basic_set_has_no_effect_before_provider_owner_exists() {
    MUTATIONS.store(0, Ordering::SeqCst);
    let mut backend = MountedVolumeBackend {
        opens: Opens, shares: Shares { open: InstalledOpen { current_offset: 0 } },
        bindings: vec![None; 77], mount: 3, captured: None,
    };
    let mut basic = [0u8; 40];
    basic[32..36].copy_from_slice(&1u32.to_le_bytes());
    let irp = IrpProjection { irp_id: 93, file_id: Some(FileId(41)),
        parameters: IoParameters::SetInformation(SetInformationParameters {
            info_class: nt_fs::FILE_BASIC_INFORMATION, length: 40,
            target_file: None, control: SetInformationControl::None,
        }) };
    let result = backend.set_file_information(
        DispatchContext { system_buffer: &basic }, &irp,
        nt_fs::LayeredOpenContextId(77),
        MountedBinding { granted_access: 0x100100, is_directory: false,
            shadows_installed: false, overlay_open: true, installed_open: None,
            overlay_body: false, context: nt_fs::LayeredOpenContextId(77) },
        match irp.parameters { IoParameters::SetInformation(p) => p },
    );
    assert_eq!(result, Ok(DispatchOutcome::Pending));
    assert_eq!(MUTATIONS.load(Ordering::SeqCst), 0);
    assert_eq!(backend.captured, Some((93, 41, 77, 3, 55, basic)));
}

#[test]
fn basic_owner_stays_valid_during_boot_route_before_native_handoff() {
    ROUTE.store(0, Ordering::SeqCst);
    let context = nt_fs::LayeredOpenContextId(77);
    let binding = MountedBinding {
        granted_access: 0x100100, is_directory: false,
        shadows_installed: false, overlay_open: false, overlay_body: true,
        installed_open: None, context,
    };
    let mut bindings = vec![None; 77];
    bindings[76] = Some(binding);
    let backend = MountedVolumeBackend {
        opens: Opens, shares: Shares { open: InstalledOpen { current_offset: 0 } },
        bindings, mount: 3, captured: None,
    };
    let owner = BasicIdentity {
        file: FileId(41), context, mount: nt_memory_manager::SectionMountId(3),
        overlay_mount: nt_memory_manager::SectionMountId(4), overlay_file: 55,
    };
    assert_eq!(backend.basic_owner_status(owner), Ok(()));
}
"#;
