//! Mounted-SYSTEM filter policy read through CM-owned key snapshots.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    Backend, ConfigClient, DriverServiceBinding, DriverServiceClass, HiveKeySnapshot,
    HiveValueSnapshot, STATUS_DEVICE_NOT_READY, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND,
};

const ENUM_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Enum";
const CLASS_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Class";
const SERVICES_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
#[cfg(test)]
const REG_SZ: u32 = 1;
const REG_MULTI_SZ: u32 = 7;

/// Filter services in the NT PnP AddDevice order around the function driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFilterPolicySnapshot {
    pub mount_generation: u64,
    pub class_guid: Option<String>,
    pub device_lower: Vec<String>,
    pub class_lower: Vec<String>,
    pub device_upper: Vec<String>,
    pub class_upper: Vec<String>,
}

/// Registry-selected upper filters in NT AddDevice order: device, then setup class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpperFilterLaunchPlanSnapshot {
    pub mount_generation: u64,
    pub policy: DeviceFilterPolicySnapshot,
    pub bindings: Vec<DriverServiceBinding>,
}

fn value<'a>(key: &'a HiveKeySnapshot, name: &str) -> Option<&'a HiveValueSnapshot> {
    key.values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
}

fn reg_sz(value: &HiveValueSnapshot) -> Result<String, i32> {
    if value.data.len() < 4 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    crate::decode_terminated_reg_sz(value.value_type, &value.data)
        .ok_or(STATUS_INVALID_PARAMETER)
}

fn filter_list(key: &HiveKeySnapshot, name: &str) -> Result<Vec<String>, i32> {
    let Some(value) = value(key, name) else {
        return Ok(Vec::new());
    };
    if value.value_type != REG_MULTI_SZ || value.data.len() < 4 || value.data.len() % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let units: Vec<_> = value
        .data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    if !units.ends_with(&[0, 0]) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut names = Vec::new();
    let mut begin = 0;
    for (index, unit) in units[..units.len() - 1].iter().enumerate() {
        if *unit != 0 {
            continue;
        }
        if index == begin {
            if units.len() == 2 {
                return Ok(names);
            }
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name =
            String::from_utf16(&units[begin..index]).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if name.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        names.push(name);
        begin = index + 1;
    }
    if begin != units.len() - 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(names)
}

fn valid_filter_service_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.chars().any(|ch| matches!(ch, '\0' | '\\' | '/'))
}

impl<B: Backend> ConfigClient<B> {
    /// Resolve real upper-filter services from the same mounted SYSTEM generation.
    pub fn query_upper_filter_launch_plan(
        &mut self,
        instance_id: &str,
    ) -> Result<Option<UpperFilterLaunchPlanSnapshot>, i32> {
        let Some(policy) = self.query_device_filter_policy(instance_id)? else {
            return Ok(None);
        };
        if policy.mount_generation == 0 {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        let filter_count = policy.device_upper.len()
            .checked_add(policy.class_upper.len())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut bindings = Vec::new();
        bindings.try_reserve_exact(filter_count).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for service_name in policy.device_upper.iter().chain(&policy.class_upper) {
            if !valid_filter_service_name(service_name) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let path = alloc::format!(r"{}\{}", SERVICES_PATH, service_name);
            let before = self.query_system_hive_key(&path)?;
            if before.mount_generation != policy.mount_generation {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            let binding = self.query_driver_service(service_name)?;
            let after = self.query_system_hive_key(&path)?;
            if after.mount_generation != policy.mount_generation || before != after {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            if !binding.service_name.eq_ignore_ascii_case(service_name)
                || binding.class != DriverServiceClass::Device
                || binding.start_type >= 4
                || binding.image_path.is_empty()
                || binding.driver_object_path.is_empty()
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            bindings.push(binding);
        }
        // Every service query is immutable, but the mounted hive may have advanced between
        // snapshots. A final reread fences the whole ordered plan to the selected generation.
        let current_policy = self.query_device_filter_policy(instance_id)?;
        if current_policy.as_ref() != Some(&policy) {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        Ok(Some(UpperFilterLaunchPlanSnapshot {
            mount_generation: policy.mount_generation,
            policy,
            bindings,
        }))
    }

    /// Read ordered per-device and setup-class filter lists for a mounted Enum instance.
    /// A missing class key supplies no class filters; malformed values fail closed.
    pub fn query_device_filter_policy(
        &mut self,
        instance_id: &str,
    ) -> Result<Option<DeviceFilterPolicySnapshot>, i32> {
        if instance_id.is_empty() || instance_id.contains('\0') || instance_id.starts_with('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let device_path = alloc::format!(r"{}\{}", ENUM_PATH, instance_id);
        let device = match self.query_system_hive_key(&device_path) {
            Ok(key) => key,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
            Err(status) => return Err(status),
        };
        let class_guid = value(&device, "ClassGUID").map(reg_sz).transpose()?;
        if class_guid
            .as_ref()
            .is_some_and(|guid| guid.is_empty() || guid.contains('\\'))
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let class = if let Some(guid) = &class_guid {
            match self.query_system_hive_key(&alloc::format!(r"{}\{}", CLASS_PATH, guid)) {
                Ok(key) => {
                    if key.mount_generation != device.mount_generation {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    Some(key)
                }
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => None,
                Err(status) => return Err(status),
            }
        } else {
            None
        };
        Ok(Some(DeviceFilterPolicySnapshot {
            mount_generation: device.mount_generation,
            class_guid,
            device_lower: filter_list(&device, "LowerFilters")?,
            class_lower: class
                .as_ref()
                .map(|key| filter_list(key, "LowerFilters"))
                .transpose()?
                .unwrap_or_default(),
            device_upper: filter_list(&device, "UpperFilters")?,
            class_upper: class
                .as_ref()
                .map(|key| filter_list(key, "UpperFilters"))
                .transpose()?
                .unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::num::NonZeroU32;
    use nt_config_manager::{encode_multi_sz, encode_sz};
    use nt_config_server::CmServer;
    use nt_hive_core::{encode_image, Hive, HiveKind, RegistryValueType};

    struct Direct(CmServer);

    impl Backend for Direct {
        fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> nt_config_abi::CmReply {
            self.0.dispatch(opcode, input, output)
        }
    }

    struct SwitchAfterService {
        before: CmServer,
        after: CmServer,
        saw_service: bool,
        switched: bool,
    }

    impl Backend for SwitchAfterService {
        fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> nt_config_abi::CmReply {
            if opcode == nt_config_abi::opcode::CM_OP_QUERY_HIVE_KEY && self.saw_service {
                self.switched = true;
            }
            let response = if self.switched {
                self.after.dispatch(opcode, input, output)
            } else {
                self.before.dispatch(opcode, input, output)
            };
            if opcode == nt_config_abi::opcode::CM_OP_QUERY_DRIVER_SERVICE {
                self.saw_service = true;
            }
            response
        }
    }

    fn switched_hive(service_image: &str, filter_name: &str) -> Hive {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let dev = hive.create_key(r"ControlSet001\Enum\ROOT\FILTERED\0000");
        hive.set_value(dev, "UpperFilters", RegistryValueType::MultiSz, encode_multi_sz(&[filter_name]));
        let service = hive.create_key(r"ControlSet001\Services\Upper");
        hive.set_dword(service, "Type", 1);
        hive.set_dword(service, "Start", 3);
        hive.set_value(service, "ImagePath", RegistryValueType::ExpandSz, encode_sz(service_image));
        hive.finish_clean_import();
        hive
    }

    fn switched_client(after: Hive) -> ConfigClient<SwitchAfterService> {
        let mut before = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(before.import_system_hive(&encode_image(&switched_hive(r"system32\drivers\upper.sys", "Upper"))), Ok(1));
        let mut after_client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(after_client.import_system_hive(&encode_image(&after)), Ok(1));
        ConfigClient::new(SwitchAfterService {
            before: before.backend.0,
            after: after_client.backend.0,
            saw_service: false,
            switched: false,
        })
    }

    #[test]
    fn mounted_policy_preserves_device_and_class_order() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let dev = hive.create_key(r"ControlSet001\Enum\ROOT\SAMPLE\0000");
        let class = hive.create_key(r"ControlSet001\Control\Class\{sample-guid}");
        hive.set_value(
            dev,
            "ClassGUID",
            RegistryValueType::Sz,
            encode_sz("{sample-guid}"),
        );
        for (key, name, names) in [
            (dev, "LowerFilters", &["device-low-a", "device-low-b"][..]),
            (class, "LowerFilters", &["class-low"][..]),
            (dev, "UpperFilters", &["device-high"][..]),
            (class, "UpperFilters", &["class-high-a", "class-high-b"][..]),
        ] {
            hive.set_value(
                key,
                name,
                RegistryValueType::MultiSz,
                encode_multi_sz(names),
            );
        }
        hive.finish_clean_import();
        let mut client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        let policy = client
            .query_device_filter_policy(r"ROOT\SAMPLE\0000")
            .unwrap()
            .unwrap();
        assert_eq!(policy.mount_generation, 1);
        assert_eq!(policy.device_lower, ["device-low-a", "device-low-b"]);
        assert_eq!(policy.class_lower, ["class-low"]);
        assert_eq!(policy.device_upper, ["device-high"]);
        assert_eq!(policy.class_upper, ["class-high-a", "class-high-b"]);
        assert_eq!(
            client.query_device_filter_policy(r"ROOT\MISSING\0000"),
            Ok(None)
        );
    }

    #[test]
    fn malformed_lists_do_not_silently_disappear() {
        let key = HiveKeySnapshot {
            mount_generation: 1,
            path: String::new(),
            class_name: None,
            security_descriptor: None,
            subkeys: Vec::new(),
            values: vec![HiveValueSnapshot {
                name: "LowerFilters".into(),
                value_type: REG_SZ,
                data: encode_sz("filter"),
            }],
        };
        assert_eq!(
            filter_list(&key, "LowerFilters"),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn upper_filter_launch_plan_resolves_device_then_class_services() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let dev = hive.create_key(r"ControlSet001\Enum\ROOT\FILTERED\0000");
        let class = hive.create_key(r"ControlSet001\Control\Class\{filtered-guid}");
        hive.set_value(dev, "ClassGUID", RegistryValueType::Sz, encode_sz("{filtered-guid}"));
        hive.set_value(dev, "UpperFilters", RegistryValueType::MultiSz, encode_multi_sz(&["DeviceUpper"]));
        hive.set_value(class, "UpperFilters", RegistryValueType::MultiSz, encode_multi_sz(&["ClassUpper"]));
        for name in ["DeviceUpper", "ClassUpper"] {
            let service = hive.create_key(&alloc::format!(r"ControlSet001\Services\{name}"));
            hive.set_dword(service, "Type", 1);
            hive.set_dword(service, "Start", 3);
            hive.set_value(
                service,
                "ImagePath",
                RegistryValueType::ExpandSz,
                encode_sz(&alloc::format!(r"system32\drivers\{name}.sys")),
            );
        }
        hive.finish_clean_import();
        let mut client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        let plan = client.query_upper_filter_launch_plan(r"ROOT\FILTERED\0000").unwrap().unwrap();
        assert_eq!(plan.mount_generation, 1);
        assert_eq!(plan.policy.device_upper, ["DeviceUpper"]);
        assert_eq!(plan.policy.class_upper, ["ClassUpper"]);
        assert_eq!(plan.bindings.iter().map(|binding| binding.service_name.as_str()).collect::<Vec<_>>(), ["DeviceUpper", "ClassUpper"]);
    }

    #[test]
    fn upper_filter_launch_plan_fails_closed_on_missing_or_non_driver_service() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let dev = hive.create_key(r"ControlSet001\Enum\ROOT\FILTERED\0000");
        hive.set_value(dev, "UpperFilters", RegistryValueType::MultiSz, encode_multi_sz(&["Missing"]));
        hive.finish_clean_import();
        let mut client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        assert_eq!(
            client.query_upper_filter_launch_plan(r"ROOT\FILTERED\0000"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
        );

        let service = hive.create_key(r"ControlSet001\Services\Missing");
        hive.set_dword(service, "Type", 0x10); // Win32 service, not a kernel driver.
        hive.set_dword(service, "Start", 3);
        hive.finish_clean_import();
        let mut client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        assert!(client.query_upper_filter_launch_plan(r"ROOT\FILTERED\0000").is_err());
    }

    #[test]
    fn upper_filter_plan_rejects_same_generation_service_or_policy_change() {
        let mut changed_service = switched_client(switched_hive(r"system32\drivers\different.sys", "Upper"));
        assert_eq!(
            changed_service.query_upper_filter_launch_plan(r"ROOT\FILTERED\0000"),
            Err(STATUS_DEVICE_NOT_READY),
        );
        let mut changed_policy = switched_client(switched_hive(r"system32\drivers\upper.sys", "OtherUpper"));
        assert_eq!(
            changed_policy.query_upper_filter_launch_plan(r"ROOT\FILTERED\0000"),
            Err(STATUS_DEVICE_NOT_READY),
        );
    }
}
