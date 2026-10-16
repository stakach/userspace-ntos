//! Exercise the native ACPI root Enum publication against recorded CM ports.

use std::process::Command;

#[test]
fn acpi_root_publication_prepares_description_before_device_install() {
    let source = include_str!("../../../components/ntos-executive/src/acpi_platform.rs");
    let constants_start = source.find("pub(crate) const ACPI_ROOT_INSTANCE_PATH:")
        .expect("native ACPI root identity constants");
    let constants_end = source[constants_start..].find("\n#[derive(Clone, Copy)]")
        .expect("end of native ACPI root identity constants") + constants_start;
    let constants = &source[constants_start..constants_end];
    syn::parse_file(constants).expect("extract complete native ACPI root identity constants");
    let functions = &source[source.find("fn encode_registry_sz(").expect("native ACPI root encoder")..];
    syn::parse_file(functions).expect("extract complete native ACPI root publication functions");
    let harness = format!("{constants}\n{PORTS}\n{functions}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-acpi-root-description-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native ACPI root fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).args(["cases::", "--nocapture"]).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "ACPI root Enum publication regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

mod nt_status {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NtStatus(pub i32);
    impl NtStatus {
        pub const INSUFFICIENT_RESOURCES: Self = Self(0xc000_009au32 as i32);
        pub const OBJECT_NAME_NOT_FOUND: Self = Self(0xc000_0034u32 as i32);
        pub const INVALID_PARAMETER: Self = Self(0xc000_000du32 as i32);
        pub const INVALID_DEVICE_REQUEST: Self = Self(0xc000_0010u32 as i32);
        pub fn raw(self) -> i32 { self.0 }
    }
}
mod nt_config_manager {
    #[repr(u32)]
    pub enum RegistryValueType { Sz = 1, MultiSz = 7 }
}
mod nt_pnp_manager {
    pub mod device_text {
        pub struct DeviceTextRegistryValue {
            pub name: &'static str,
            pub value_type: u32,
            pub data: Vec<u8>,
        }
        pub fn reactos_unknown_device_description() -> Result<DeviceTextRegistryValue, ()> {
            Ok(DeviceTextRegistryValue {
                name: "DeviceDesc",
                value_type: 1,
                data: "Unknown device".encode_utf16().chain(std::iter::once(0))
                    .flat_map(u16::to_le_bytes).collect(),
            })
        }
    }
}
mod nt_config_client {
    #[derive(Clone)]
    pub struct CriticalDeviceBinding {
        pub mount_generation: u64,
        pub class_guid: String,
        pub service_name: Option<String>,
    }
    #[derive(Clone)]
    pub struct HiveValueSnapshot {
        pub name: String,
        pub value_type: u32,
        pub data: Vec<u8>,
    }
    #[derive(Clone)]
    pub struct HiveKeySnapshot {
        pub mount_generation: u64,
        pub values: Vec<HiveValueSnapshot>,
    }
    pub enum SystemHiveMutation<'a> {
        CreateKey { path: &'a str },
        SetValue { path: &'a str, name: &'a str, value_type: u32, data: &'a [u8] },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecordedMutation {
    CreateKey { path: String },
    SetValue { path: String, name: String, value_type: u32, data: Vec<u8> },
}
#[derive(Default)]
struct CmState {
    existing: Option<nt_config_client::HiveKeySnapshot>,
    writes: Vec<RecordedMutation>,
}
thread_local! { static CM: RefCell<CmState> = RefCell::new(CmState::default()); }
static LIVE_CONFIG_MANAGER_SYSTEM_GENERATION: AtomicU64 = AtomicU64::new(7);

fn config_manager_query_critical_device_binding(
    id: &str,
) -> Result<Option<nt_config_client::CriticalDeviceBinding>, i32> {
    assert_eq!(id, ACPI_ROOT_COMPATIBLE_ID);
    Ok(Some(nt_config_client::CriticalDeviceBinding {
        mount_generation: 7,
        class_guid: "{4D36E97D-E325-11CE-BFC1-08002BE10318}".into(),
        service_name: Some("acpi".into()),
    }))
}
fn config_manager_query_system_hive_key(
    path: &str,
) -> Result<nt_config_client::HiveKeySnapshot, i32> {
    assert_eq!(path, ACPI_ROOT_ENUM_PATH);
    CM.with(|cm| cm.borrow().existing.clone())
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND.raw())
}
mod boot_registry_mutation_work {
    use super::*;

    pub enum BootRegistryStage { AcpiRoot }
    pub struct MutationOutcome { pub generation: u64 }

    pub fn publish_boot_system_mutation(
        stage: BootRegistryStage,
        generation: u64,
        mutations: &[nt_config_client::SystemHiveMutation<'_>],
    ) -> Result<MutationOutcome, u32> {
        assert!(matches!(stage, BootRegistryStage::AcpiRoot));
        assert_eq!(generation, 7);
        CM.with(|cm| {
            let mut state = cm.borrow_mut();
            state.writes.extend(mutations.iter().map(|mutation| match mutation {
                nt_config_client::SystemHiveMutation::CreateKey { path } =>
                    RecordedMutation::CreateKey { path: (*path).into() },
                nt_config_client::SystemHiveMutation::SetValue { path, name, value_type, data } =>
                    RecordedMutation::SetValue {
                        path: (*path).into(), name: (*name).into(),
                        value_type: *value_type, data: data.to_vec(),
                    },
            }));
        });
        // The native caller proceeds only after this exact CM generation is acknowledged.
        Ok(MutationOutcome { generation: generation + 1 })
    }
}
"#;

const CASES: &str = r#"
#[cfg(test)] mod cases {
use super::*;

fn value(name: &str, data: &[u8]) -> RecordedMutation {
    RecordedMutation::SetValue {
        path: ACPI_ROOT_ENUM_PATH.into(), name: name.into(),
        value_type: nt_config_manager::RegistryValueType::Sz as u32,
        data: data.to_vec(),
    }
}
fn sz(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes).collect()
}
fn assert_description(writes: &[RecordedMutation]) {
    let descriptions: Vec<_> = writes.iter().filter(|write| matches!(write,
        RecordedMutation::SetValue { name, .. } if name == "DeviceDesc"
    )).collect();
    assert_eq!(descriptions.len(), 1, "Enum DeviceDesc must be durable before device install");
    let RecordedMutation::SetValue { path, value_type, data, .. } = descriptions[0] else { unreachable!() };
    assert_eq!(path, ACPI_ROOT_ENUM_PATH);
    assert_eq!(*value_type, nt_config_manager::RegistryValueType::Sz as u32);
    assert!(data.len() >= 4 && data.len() % 2 == 0 && data.ends_with(&[0, 0]),
        "description must be a nonempty terminated UTF-16 REG_SZ");
}

#[test]
fn first_publication_writes_device_description_with_policy() {
    CM.with(|cm| *cm.borrow_mut() = CmState::default());
    unsafe { publish_acpi_root_devnode_from_registry_policy().unwrap() };
    let writes = CM.with(|cm| cm.borrow().writes.clone());
    assert!(writes.contains(&RecordedMutation::CreateKey { path: ACPI_ROOT_ENUM_PATH.into() }));
    assert_description(&writes);
    assert!(writes.contains(&value("Service", &sz("acpi"))),
        "the critical-device service binding must remain acpi");
    assert!(writes.contains(&value("ClassGUID", &sz("{4D36E97D-E325-11CE-BFC1-08002BE10318}"))),
        "the critical-device class binding must remain intact");
}

#[test]
fn existing_enum_key_without_description_is_completed() {
    CM.with(|cm| {
        *cm.borrow_mut() = CmState {
            existing: Some(nt_config_client::HiveKeySnapshot {
                mount_generation: 7,
                values: [
                    ("HardwareID", nt_config_manager::RegistryValueType::MultiSz as u32,
                        super::encode_registry_multi_sz(&[ACPI_ROOT_HARDWARE_ID]).unwrap()),
                    ("CompatibleIDs", nt_config_manager::RegistryValueType::MultiSz as u32,
                        super::encode_registry_multi_sz(&[ACPI_ROOT_COMPATIBLE_ID]).unwrap()),
                    ("ClassGUID", nt_config_manager::RegistryValueType::Sz as u32,
                        sz("{4D36E97D-E325-11CE-BFC1-08002BE10318}")),
                    ("Service", nt_config_manager::RegistryValueType::Sz as u32, sz("acpi")),
                ].into_iter().map(|(name, value_type, data)| nt_config_client::HiveValueSnapshot {
                    name: name.into(), value_type, data,
                }).collect(),
            }),
            writes: Vec::new(),
        };
    });
    unsafe { publish_acpi_root_devnode_from_registry_policy().unwrap() };
    let writes = CM.with(|cm| cm.borrow().writes.clone());
    assert!(!writes.iter().any(|write| matches!(write, RecordedMutation::CreateKey { .. })));
    assert_description(&writes);
    assert!(writes.iter().all(|write| matches!(write,
        RecordedMutation::SetValue { name, .. } if name == "DeviceDesc"
    )), "existing policy bindings need no replacement when only DeviceDesc is absent");
}

#[test]
fn existing_device_description_survives_policy_refresh() {
    let real_description = sz("ACPI firmware root");
    CM.with(|cm| {
        *cm.borrow_mut() = CmState {
            existing: Some(nt_config_client::HiveKeySnapshot {
                mount_generation: 7,
                values: [
                    ("DeviceDesc", nt_config_manager::RegistryValueType::Sz as u32,
                        real_description.clone()),
                    ("Service", nt_config_manager::RegistryValueType::Sz as u32,
                        sz("old-service")),
                ].into_iter().map(|(name, value_type, data)| nt_config_client::HiveValueSnapshot {
                    name: name.into(), value_type, data,
                }).collect(),
            }),
            writes: Vec::new(),
        };
    });
    unsafe { publish_acpi_root_devnode_from_registry_policy().unwrap() };
    let writes = CM.with(|cm| cm.borrow().writes.clone());
    assert!(writes.contains(&value("Service", &sz("acpi"))));
    assert!(!writes.iter().any(|write| matches!(write,
        RecordedMutation::SetValue { name, .. } if name.eq_ignore_ascii_case("DeviceDesc")
    )), "the firmware root's real description must survive a policy refresh");
}
}
"#;
